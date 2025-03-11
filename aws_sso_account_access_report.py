import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import csv
from typing import Dict, List, Tuple

import boto3
from retry import retry


# Read configuration
config = configparser.ConfigParser()
config.read("config.ini")

region = config.get("DEFAULT", "region")
identity_store_id = config.get("DEFAULT", "identity_store_id")
sso_instance_arn = config.get("DEFAULT", "sso_instance_arn")
aws_org_id = config.get("DEFAULT", "org_id")
num_workers = int(config.get("DEFAULT", "num_workers"))
max_retries = int(config.get("DEFAULT", "max_retries"))

# Get optional account filter (comma-separated list of account IDs)
account_filter_str = config.get("DEFAULT", "account_filter", fallback="")
account_filter = [account.strip() for account in account_filter_str.split(",")] if account_filter_str else []


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def list_groups(identity_store_id: str, region: str) -> List[Dict[str, str]]:
    """
    List groups in Identity Store.

    :param identity_store_id: The ID of the Identity Store.
    :param region: The AWS region.
    :return: A list of groups.
    """
    identity_store_client = boto3.client("identitystore", region_name=region)
    groups = []

    paginator = identity_store_client.get_paginator("list_groups")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        groups.extend(page["Groups"])

    return groups


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def list_users(identity_store_id: str, region: str) -> List[Dict[str, str]]:
    """
    List users in Identity Store.

    :param identity_store_id: The ID of the Identity Store.
    :param region: The AWS region.
    :return: A list of users.
    """
    identity_store_client = boto3.client("identitystore", region_name=region)
    users = []

    paginator = identity_store_client.get_paginator("list_users")
    for page in paginator.paginate(IdentityStoreId=identity_store_id):
        users.extend(page["Users"])

    return users


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def get_account_assignments(
    sso_instance_arn: str, account_id: str, permission_set_arn: str, region: str
) -> List[Dict[str, str]]:
    """
    Get account assignments for a given account and permission set.

    :param sso_instance_arn: The ARN of the SSO instance.
    :param account_id: The ID of the AWS account.
    :param permission_set_arn: The ARN of the permission set.
    :param region: The AWS region.
    :return: A list of account assignments.
    """
    sso_admin_client = boto3.client("sso-admin", region_name=region)

    paginator = sso_admin_client.get_paginator("list_account_assignments")
    response_iterator = paginator.paginate(
        InstanceArn=sso_instance_arn,
        AccountId=account_id,
        PermissionSetArn=permission_set_arn,
    )

    account_assignments = []
    for response in response_iterator:
        account_assignments.extend(response["AccountAssignments"])

    return account_assignments


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def list_permission_set_arns(sso_instance_arn: str, region: str) -> List[str]:
    """
    List permission set ARNs for an SSO instance.

    :param sso_instance_arn: The ARN of the SSO instance.
    :param region: The AWS region.
    :return: A list of permission set ARNs.
    """
    sso_admin_client = boto3.client("sso-admin", region_name=region)

    paginator = sso_admin_client.get_paginator("list_permission_sets")
    response_iterator = paginator.paginate(InstanceArn=sso_instance_arn)

    permission_set_arns = []
    for response in response_iterator:
        permission_set_arns.extend(response["PermissionSets"])

    return permission_set_arns


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def get_permission_set_name(
    permission_set_arn: str, sso_instance_arn: str, region: str
) -> str:
    """
    Get the name of a permission set.

    :param permission_set_arn: The ARN of the permission set.
    :param sso_instance_arn: The ARN of the SSO instance.
    :param region: The AWS region.
    :return: The name of the permission set.
    """
    sso_admin_client = boto3.client("sso-admin", region_name=region)
    response = sso_admin_client.describe_permission_set(
        InstanceArn=sso_instance_arn, PermissionSetArn=permission_set_arn
    )
    return response["PermissionSet"]["Name"]


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def list_accounts(org_id: str, region: str) -> List[Dict[str, str]]:
    """
    List AWS Organization accounts.

    :param org_id: The ID of the AWS Organization.
    :param region: The AWS region.
    :return: A list of AWS Organization accounts.
    """
    org_client = boto3.client("organizations", region_name=region)

    paginator = org_client.get_paginator("list_accounts")
    response_iterator = paginator.paginate()

    accounts = []
    for response in response_iterator:
        accounts.extend(response["Accounts"])

    return accounts


@retry(tries=max_retries, jitter=(0, 3), delay=1, backoff=2, max_delay=3)
def list_user_ids_for_group(
    identity_store_id: str, group_id: str, region: str
) -> List[str]:
    """
    List user IDs for a specific group in Identity Store.

    :param identity_store_id: The ID of the Identity Store.
    :param group_id: The ID of the group.
    :param region: The AWS region.
    :return: A list of user IDs belonging to the specified group.
    """
    identity_store_client = boto3.client("identitystore", region_name=region)
    paginator = identity_store_client.get_paginator("list_group_memberships")
    response_iterator = paginator.paginate(
        IdentityStoreId=identity_store_id, GroupId=group_id
    )

    user_ids = []
    # Extract user IDs from the group memberships and add them to user_ids list
    for response in response_iterator:
        user_ids.extend(
            [
                membership["MemberId"]["UserId"]
                for membership in response["GroupMemberships"]
            ]
        )

    return user_ids


def process_account(
    account: Dict[str, str],
    perm_sets: List[str],
    groups: List[Dict[str, str]],
    users: List[Dict[str, str]],
    group_members_details: List[Dict[str, List[str]]],
) -> List[Tuple[str, str, str, str]]:
    """
    Process an AWS account and retrieve members with account access.

    :param account: A dictionary containing the account ID and name.
    :param perm_sets: A list of permission set ARNs.
    :param groups: A list of dictionaries containing SSO group information.
    :param users: A list of dictionaries containing SSO user information.
    :param group_members_details: A list of dictionaries containing group member details.
    :return: A list of tuples containing account ID, account name, user account, and permission set name.
    """
    logging.info(f"Processing account: {account['Id']} - {account['Name']}")

    members_with_account_access = []

    # Iterate through permission sets
    for permission_set in perm_sets:
        permission_set_name = get_permission_set_name(
            permission_set, sso_instance_arn, region
        )
        group_assignment = get_account_assignments(
            sso_instance_arn, account["Id"], permission_set, region
        )

        # Check if there's any group assignment
        if group_assignment:
            for group_assn in group_assignment:
                # Process group assignments
                if group_assn["PrincipalType"] == "GROUP":
                    for group in groups:
                        if group_assn["PrincipalId"] == group["GroupId"]:
                            for group_member_detail in group_members_details:
                                if group["DisplayName"] in group_member_detail.keys():
                                    for group_details in group_member_detail.values():
                                        for member in group_details:
                                            members_with_account_access.append(
                                                (
                                                    account["Id"],
                                                    account["Name"],
                                                    group["DisplayName"],
                                                    member,
                                                    permission_set_name,
                                                )
                                            )
                # Process user assignments
                elif group_assn["PrincipalType"] == "USER":
                    for user in users:
                        if group_assn["PrincipalId"] == user["UserId"]:
                            members_with_account_access.append(
                                (
                                    account["Id"],
                                    account["Name"],
                                    "Not Group Assigned",
                                    user["UserName"],
                                    permission_set_name,
                                )
                            )
    # Remove duplicate entries and return the result
    return list(set(members_with_account_access))


def main() -> None:
    """
    The main function of the script.

    Fetches the necessary data, processes accounts in parallel, and writes the results to a CSV file.
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Fetch information about organization accounts, permission sets, SSO groups, and SSO users
    logging.info(
        f"Getting info on org_accounts, permission sets, SSO groups and SSO users"
    )
    org_accounts = list_accounts(aws_org_id, region)
    
    # Filter accounts if account_filter is specified
    if account_filter:
        logging.info(f"Filtering accounts based on account filter: {account_filter}")
        org_accounts = [account for account in org_accounts if account["Id"] in account_filter]
        logging.info(f"Filtered to {len(org_accounts)} accounts")
    perm_sets = list_permission_set_arns(sso_instance_arn, region)
    groups = list_groups(identity_store_id, region)
    users = list_users(identity_store_id, region)

    # Fetch group member details
    logging.info(f"Getting info group_members_details")
    group_members_details = []
    for group in groups:
        logging.info(f"Getting info for {group}")
        group_name = group["DisplayName"]
        group_member_names = []

        group_member_ids = list_user_ids_for_group(
            identity_store_id, group["GroupId"], region
        )
        for group_member_id in group_member_ids:
            for user in users:
                if user["UserId"] == group_member_id:
                    group_member_names.append(user["UserName"])

        group_member_names = list(set(group_member_names))
        group_members_details.append({group_name: group_member_names})

    # Write the header row for CSV
    logging.info(f"Write CSV Header row")
    header = ["AccountID", "Account Name", "Group", "User Account", "Permission Set"]
    with open("output.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)

    # Process accounts in parallel using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [
            executor.submit(
                process_account,
                account,
                perm_sets,
                groups,
                users,
                group_members_details,
            )
            for account in org_accounts
        ]

        # Iterate through completed futures and write results to CSV
        for future in as_completed(futures):
            members_with_account_access = future.result()

            # Write results to CSV
            with open("output.csv", "a", newline="") as f:
                writer = csv.writer(f)
                for row in members_with_account_access:
                    writer.writerow(row)

            logging.info(f"Completed processing account: {row[0]} - {row[1]}")


if __name__ == "__main__":
    main()
