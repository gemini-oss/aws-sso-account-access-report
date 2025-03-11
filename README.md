# AWS SSO Account Access Report
This script generates a CSV report of user access to AWS accounts managed by AWS Single Sign-On (SSO). The report includes AWS Organization accounts, permission sets, SSO groups, and SSO users.

## Prerequisites
- Python 3.10.8
- AWS account credentials with appropriate read-only permissions to access AWS SSO, AWS Organizations, and AWS Identity Store

## Configuration
- Export your AWS Access creds to the environment
- Update the config.ini file with the following information:
```
[DEFAULT]
region = <AWS_REGION>
identity_store_id = <IDENTITY_STORE_ID>
sso_instance_arn = <SSO_INSTANCE_ARN>
org_id = <AWS_ORG_ID>
num_workers = <INT_NUM_WORKERS>
max_retries = <INT_MAX_RETRIES>
# Optional: Comma-separated list of account IDs to filter processing
account_filter = <COMMA_SEPARATED_ACCOUNT_IDS>
```

Replace <AWS_REGION>, <IDENTITY_STORE_ID>, <SSO_INSTANCE_ARN>, and <AWS_ORG_ID> with the appropriate values for your environment.

## Installation
- Clone the repository
- Change to the repository directory
- Install the required dependencies
```
pip install -r requirements.txt
```

## Usage
Run the script:
- export AWS account credentials to the environments
```
python aws_sso_account_access_report.py
```
The script will generate a CSV file named output.csv containing the account access report with the following columns:

"AccountID", "Account Name", "Group", "User Account", "Permission Set"

### Account Filtering

By default, the script processes all accounts in your AWS Organization. If you want to limit processing to specific accounts:

1. Edit the `config.ini` file
2. Add a comma-separated list of AWS account IDs to the `account_filter` parameter:
```
account_filter = 123456789012,234567890123
```

This will make the script only process the specified accounts, which can significantly reduce execution time when you only need information for a subset of accounts.
