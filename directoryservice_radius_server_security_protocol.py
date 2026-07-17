#!/usr/bin/env python3
"""
Control: Directory Service directory RADIUS server uses MS-CHAPv2.

Checks every Directory Service directory in every enabled region and
verifies that RADIUS (MFA) is both configured AND set to MS-CHAPv2.

A directory with RADIUS/MFA disabled is treated as NON_COMPLIANT (not
skipped), since the absence of MFA is itself a compliance failure.
Directories whose type does not support RADIUS at all (e.g. shared
directories, where the owner account controls RADIUS settings) are
still marked SKIPPED, since the check is genuinely not applicable there.
"""

import boto3
import argparse
import csv
from datetime import datetime
from tqdm import tqdm
from botocore.exceptions import ClientError

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
def error_evidence(e):
    """Classify a ClientError into a short code + human-readable evidence string."""
    code = e.response.get("Error", {}).get("Code", "UnknownError")
    msg = e.response.get("Error", {}).get("Message", str(e))
    return code, f"{code}: {msg}"[:200]


# RADIUS/MFA is not supported for shared directories - the owner account
# controls RADIUS settings, not the account the directory is shared into.
# This is a genuine "not applicable" case, so it stays SKIPPED.
UNSUPPORTED_TYPES = {"SharedMicrosoftAD"}

REQUIRED_PROTOCOL = "MS-CHAPv2"


def build_arn(region, account_id, directory_id):
    return f"arn:aws:ds:{region}:{account_id}:directory/{directory_id}"


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
            ds = session.client("ds", region_name=region)
            paginator = ds.get_paginator("describe_directories")
            directories = []
            for page in paginator.paginate():
                directories.extend(page.get("DirectoryDescriptions", []))
        except ClientError as e:
            code, evidence = error_evidence(e)
            skipped += 1
            results.append({
                "Region": region,
                "DirectoryId": "N/A",
                "DirectoryArn": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for directory in directories:
            total_checked += 1
            directory_id = directory.get("DirectoryId", "N/A")
            directory_arn = build_arn(region, account_id, directory_id)
            dir_type = directory.get("Type", "Unknown")
            stage = directory.get("Stage", "Unknown")

            # --- Skip directory types that don't support RADIUS/MFA at all ---
            if dir_type in UNSUPPORTED_TYPES:
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"RADIUS/MFA not supported for directory type '{dir_type}'"
                })
                continue

            if stage != "Active":
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"Directory not in Active stage (current stage: {stage})"
                })
                continue

            radius_settings = directory.get("RadiusSettings")
            radius_status = directory.get("RadiusStatus", "Disabled")

            # --- RADIUS not configured at all: this IS a compliance failure ---
            if not radius_settings or radius_status == "Disabled":
                non_compliant += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "Status": "NON_COMPLIANT",
                    "Evidence": "RADIUS/MFA is not configured on this directory (MFA is not enforced)"
                })
                continue

            # --- RADIUS configured but not yet ready (e.g. still creating) ---
            if radius_status != "Completed":
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "Status": "SKIPPED",
                    "Evidence": f"RADIUS configuration not in Completed state (status: {radius_status})"
                })
                continue

            protocol = radius_settings.get("AuthenticationProtocol", "Unknown")

            if protocol == REQUIRED_PROTOCOL:
                status = "COMPLIANT"
                compliant += 1
                evidence = f"RADIUS authentication protocol is {protocol}"
            else:
                status = "NON_COMPLIANT"
                non_compliant += 1
                evidence = f"RADIUS authentication protocol is {protocol}, expected {REQUIRED_PROTOCOL}"

            results.append({
                "Region": region,
                "DirectoryId": directory_id,
                "DirectoryArn": directory_arn,
                "Status": status,
                "Evidence": evidence
            })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"ds_radius_mschapv2_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "DirectoryId", "DirectoryArn", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "DirectoryId": row["DirectoryId"],
                "DirectoryArn": row["DirectoryArn"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Directory Service directories for RADIUS/MFA enabled with MS-CHAPv2 protocol."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Directory Service - RADIUS Server Uses MS-CHAPv2"

    results, total_checked, compliant, non_compliant, skipped = check_control(session)

    overall = "COMPLIANT" if non_compliant == 0 else "NON_COMPLIANT"

    csv_file = write_csv(results, account_id)

    print("\n====================================================")
    print(f"CONTROL: {control_name}")
    print(f"ACCOUNT: {account_id}")
    print("====================================================")
    print(f"Total Checked   : {total_checked}")
    print(f"Compliant       : {compliant}")
    print(f"Non-Compliant   : {non_compliant}")
    print(f"Skipped         : {skipped}")
    print(f"Overall Status  : {overall}")
    print(f"CSV Report      : {csv_file}")
    print("====================================================\n")


if __name__ == "__main__":
    main()
