#!/usr/bin/env python3
"""
Control: Directory Service Directory Has Log Forwarding to CloudWatch
Logs Enabled
------------------------------------------------------------------------
Directory Service is a REGIONAL service - scanned across every opted-in
region.

Log forwarding to CloudWatch Logs is only supported by AWS Managed
Microsoft AD (Type == "MicrosoftAD" or "SharedMicrosoftAD"). Simple AD
and AD Connector directories (Type == "SimpleAD" or "ADConnector") do
not support this feature at all - they are marked SKIPPED (not
applicable) rather than forced into a compliant/non-compliant verdict.

For applicable directories, list_log_subscriptions(DirectoryId=...)
returns a LogSubscriptions list:
  - non-empty -> forwarding is configured, with a target log group name
  - empty     -> forwarding is not configured

Compliant     -> applicable directory type AND at least one active log
                  subscription
Non-compliant -> applicable directory type AND no log subscriptions
Skipped       -> unsupported directory type (SimpleAD / ADConnector), or
                  the API call itself failed (access denied, throttling,
                  etc.)
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Directory Service Directory Has Log Forwarding to CloudWatch Logs Enabled"
SUPPORTED_TYPES = {"MicrosoftAD", "SharedMicrosoftAD"}

# ==================================================
# AUTH
# ==================================================
def get_session(role_arn=None):
    if role_arn:
        base = boto3.Session()
        sts = base.client("sts")
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="control-audit"
        )
        creds = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    return boto3.Session()


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


# ==================================================
# REGIONS
# ==================================================
def get_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=True)["Regions"]
    return [
        r["RegionName"]
        for r in regions
        if r.get("OptInStatus") in ["opt-in-not-required", "opted-in"]
    ]


# ==================================================
# HELPERS
# ==================================================
def classify_error(e: ClientError) -> str:
    """Map a ClientError to a short, human-readable skip reason."""
    code = e.response.get("Error", {}).get("Code", "Unknown")
    reasons = {
        "AccessDenied": "Access denied - insufficient IAM permissions",
        "AccessDeniedException": "Access denied - insufficient IAM permissions",
        "UnrecognizedClientException": "Auth/token issue - unable to authenticate",
        "ExpiredToken": "Session token expired",
        "ClientException": "Directory Service request error - skipped",
        "EntityDoesNotExistException": "Directory not found (may have been deleted mid-scan)",
        "ThrottlingException": "Throttled by AWS API - skipped",
        "InvalidClientTokenId": "Invalid credentials",
    }
    return reasons.get(code, f"Skipped due to error [{code}]")


def evaluate_directory(client, directory: dict):
    """
    Returns (status, evidence) for a single directory. Directories whose
    type does not support log forwarding are SKIPPED (not applicable)
    rather than evaluated.
    """
    directory_type = directory.get("Type", "Unknown")
    directory_id = directory.get("DirectoryId", "N/A")

    if directory_type not in SUPPORTED_TYPES:
        return (
            "SKIPPED",
            f"Directory type '{directory_type}' does not support log "
            f"forwarding to CloudWatch Logs - not applicable"
        )

    try:
        response = client.list_log_subscriptions(DirectoryId=directory_id)
    except ClientError as e:
        return "SKIPPED", classify_error(e)

    subscriptions = response.get("LogSubscriptions", [])

    if subscriptions:
        log_groups = ", ".join(s.get("LogGroupName", "unknown") for s in subscriptions)
        return "COMPLIANT", f"Log forwarding enabled to: {log_groups}"

    return "NON_COMPLIANT", "No CloudWatch Logs log subscription configured for this directory"


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session):
    account_id = get_account_id(session)
    regions = get_regions(session)

    results = []
    total_checked = 0
    compliant = 0
    non_compliant = 0
    skipped = 0

    print(f"\nRegions to Scan: {len(regions)}\n")

    for region in tqdm(regions, desc="Scanning Regions"):
        try:
            client = session.client("ds", region_name=region)
            paginator = client.get_paginator("describe_directories")
            directories = []
            for page in paginator.paginate():
                directories.extend(page.get("DirectoryDescriptions", []))
        except ClientError as e:
            skipped += 1
            results.append({
                "Region": region,
                "DirectoryId": "N/A",
                "DirectoryType": "N/A",
                "Status": "SKIPPED",
                "Evidence": classify_error(e)
            })
            continue

        for directory in directories:
            directory_id = directory.get("DirectoryId", "N/A")
            directory_type = directory.get("Type", "Unknown")
            total_checked += 1

            status, evidence = evaluate_directory(client, directory)

            if status == "COMPLIANT":
                compliant += 1
            elif status == "NON_COMPLIANT":
                non_compliant += 1
            else:
                skipped += 1

            results.append({
                "Region": region,
                "DirectoryId": directory_id,
                "DirectoryType": directory_type,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped, account_id


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    filename = f"directoryservice_cloudwatch_log_forwarding_{account_id}.csv"
    fieldnames = ["Account", "Region", "DirectoryId", "DirectoryType", "Status", "Evidence"]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "DirectoryId": row["DirectoryId"],
                "DirectoryType": row["DirectoryType"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(description=CONTROL_NAME)
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)

    results, total_checked, compliant, non_compliant, skipped, account_id = check_control(session)
    overall_status = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n" + "=" * 60)
    print(f"CONTROL: {CONTROL_NAME}")
    print(f"ACCOUNT: {account_id}")
    print("=" * 60)
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall_status}")
    print("=" * 60)
    print(f"CSV report generated: {csv_file}\n")


if __name__ == "__main__":
    main()