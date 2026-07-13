#!/usr/bin/env python3
"""
Control: Directory Service Directory Has SNS Notifications Enabled
------------------------------------------------------------------------
Directory Service is a REGIONAL service - scanned across every opted-in
region.

Unlike CloudWatch log forwarding (Microsoft AD only), SNS event
notifications are supported by ALL Directory Service directory types
(Simple AD, AWS Managed Microsoft AD, AD Connector) - no applicability
filtering by directory Type is needed here.

describe_event_topics(DirectoryId=...) returns an EventTopics list. Each
entry has a Status field:
  - "Registered" -> the SNS topic is actively subscribed to directory
                     status change events
  - "Deleted"     -> the topic was removed/unregistered

Compliant     -> at least one EventTopic with Status == "Registered"
Non-compliant -> EventTopics is empty, or every entry is "Deleted"
Skipped       -> the API call itself failed (access denied, throttling,
                  etc.)
"""

import boto3
import argparse
import csv
from tqdm import tqdm
from botocore.exceptions import ClientError

CONTROL_NAME = "Directory Service Directory Has SNS Notifications Enabled"

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
    Returns (status, evidence) for a single directory based on its
    registered SNS event topics.
    """
    directory_id = directory.get("DirectoryId", "N/A")

    try:
        response = client.describe_event_topics(DirectoryId=directory_id)
    except ClientError as e:
        return "SKIPPED", classify_error(e)

    topics = response.get("EventTopics", [])
    registered = [t for t in topics if t.get("Status") == "Registered"]

    if registered:
        topic_names = ", ".join(t.get("TopicName", "unknown") for t in registered)
        return "COMPLIANT", f"SNS notifications enabled via topic(s): {topic_names}"

    if topics:
        return (
            "NON_COMPLIANT",
            f"{len(topics)} SNS topic(s) found, but none in 'Registered' status"
        )

    return "NON_COMPLIANT", "No SNS event topic configured for this directory"


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
    filename = f"directoryservice_sns_notifications_{account_id}.csv"
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