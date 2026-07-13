#!/usr/bin/env python3
"""
Control: Directory Service directory LDAP certificate expires in more than 90 days.

Checks every Directory Service directory (that supports certificate-based
LDAP / client certificate authentication) in every enabled region, and
verifies that all registered certificates have more than a configurable
number of days remaining before expiry.
"""

import boto3
import argparse
import csv
from datetime import datetime, timezone
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


# Certificate-based / secure LDAP auth is only supported on these directory types.
UNSUPPORTED_TYPES = {"ADConnector", "SimpleAD"}


def build_arn(region, account_id, directory_id):
    return f"arn:aws:ds:{region}:{account_id}:directory/{directory_id}"


def days_remaining(expiry_dt):
    now = datetime.now(timezone.utc)
    return (expiry_dt - now).days


# ==================================================
# CONTROL LOGIC
# ==================================================
def check_control(session, min_days_remaining=90):
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
                "CertificateId": "N/A",
                "Status": "SKIPPED",
                "Evidence": evidence
            })
            continue

        for directory in directories:
            directory_id = directory.get("DirectoryId", "N/A")
            directory_arn = build_arn(region, account_id, directory_id)
            dir_type = directory.get("Type", "Unknown")
            stage = directory.get("Stage", "Unknown")

            # --- Skip directory types that don't support certificate-based LDAP auth ---
            if dir_type in UNSUPPORTED_TYPES:
                total_checked += 1
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "CertificateId": "N/A",
                    "Status": "SKIPPED",
                    "Evidence": f"Certificate-based LDAP auth not supported for directory type '{dir_type}'"
                })
                continue

            if stage != "Active":
                total_checked += 1
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "CertificateId": "N/A",
                    "Status": "SKIPPED",
                    "Evidence": f"Directory not in Active stage (current stage: {stage})"
                })
                continue

            # --- List certificates registered on the directory ---
            try:
                cert_paginator = ds.get_paginator("list_certificates")
                certificates = []
                for page in cert_paginator.paginate(DirectoryId=directory_id):
                    certificates.extend(page.get("CertificatesInfo", []))
            except ClientError as e:
                code, evidence = error_evidence(e)
                total_checked += 1
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "CertificateId": "N/A",
                    "Status": "SKIPPED",
                    "Evidence": evidence
                })
                continue

            if not certificates:
                total_checked += 1
                skipped += 1
                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "CertificateId": "N/A",
                    "Status": "SKIPPED",
                    "Evidence": "No LDAP certificates registered on this directory"
                })
                continue

            # --- Evaluate each registered certificate ---
            for cert_info in certificates:
                total_checked += 1
                cert_id = cert_info.get("CertificateId", "N/A")
                cert_state = cert_info.get("State", "Unknown")

                try:
                    detail = ds.describe_certificate(
                        DirectoryId=directory_id,
                        CertificateId=cert_id
                    )["Certificate"]
                    expiry = detail.get("ExpiryDateTime")
                except ClientError as e:
                    code, evidence = error_evidence(e)
                    skipped += 1
                    results.append({
                        "Region": region,
                        "DirectoryId": directory_id,
                        "DirectoryArn": directory_arn,
                        "CertificateId": cert_id,
                        "Status": "SKIPPED",
                        "Evidence": evidence
                    })
                    continue

                if cert_state != "Registered":
                    skipped += 1
                    results.append({
                        "Region": region,
                        "DirectoryId": directory_id,
                        "DirectoryArn": directory_arn,
                        "CertificateId": cert_id,
                        "Status": "SKIPPED",
                        "Evidence": f"Certificate is not in Registered state (state: {cert_state})"
                    })
                    continue

                if not expiry:
                    skipped += 1
                    results.append({
                        "Region": region,
                        "DirectoryId": directory_id,
                        "DirectoryArn": directory_arn,
                        "CertificateId": cert_id,
                        "Status": "SKIPPED",
                        "Evidence": "Expiry date not available for this certificate"
                    })
                    continue

                remaining = days_remaining(expiry)

                if remaining > min_days_remaining:
                    status = "COMPLIANT"
                    compliant += 1
                    evidence = (
                        f"Certificate expires on {expiry.strftime('%Y-%m-%d')} "
                        f"({remaining} days remaining, above minimum of {min_days_remaining})"
                    )
                else:
                    status = "NON_COMPLIANT"
                    non_compliant += 1
                    if remaining < 0:
                        evidence = f"Certificate expired on {expiry.strftime('%Y-%m-%d')} ({abs(remaining)} days ago)"
                    else:
                        evidence = (
                            f"Certificate expires on {expiry.strftime('%Y-%m-%d')} "
                            f"({remaining} days remaining, at or below minimum of {min_days_remaining})"
                        )

                results.append({
                    "Region": region,
                    "DirectoryId": directory_id,
                    "DirectoryArn": directory_arn,
                    "CertificateId": cert_id,
                    "Status": status,
                    "Evidence": evidence
                })

    return results, total_checked, compliant, non_compliant, skipped


# ==================================================
# CSV
# ==================================================
def write_csv(results, account_id):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = f"ds_ldap_certificate_expiry_{account_id}_{timestamp}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["Account", "Region", "DirectoryId", "DirectoryArn", "CertificateId", "Status", "Evidence"]
        )
        writer.writeheader()
        for row in results:
            writer.writerow({
                "Account": account_id,
                "Region": row["Region"],
                "DirectoryId": row["DirectoryId"],
                "DirectoryArn": row["DirectoryArn"],
                "CertificateId": row["CertificateId"],
                "Status": row["Status"],
                "Evidence": row["Evidence"]
            })

    return filename


# ==================================================
# MAIN
# ==================================================
def main():
    parser = argparse.ArgumentParser(
        description="Check Directory Service LDAP certificates for expiry beyond a minimum number of days."
    )
    parser.add_argument("-R", "--role-arn", help="IAM Role ARN to assume", default=None)
    parser.add_argument(
        "--min-days-remaining",
        type=int,
        default=90,
        help="Minimum number of days a certificate must have left to be COMPLIANT (default: 90)"
    )
    args = parser.parse_args()

    session = get_session(args.role_arn)
    account_id = get_account_id(session)

    control_name = "Directory Service - LDAP Certificate Expires in More Than 90 Days"

    results, total_checked, compliant, non_compliant, skipped = check_control(
        session, min_days_remaining=args.min_days_remaining
    )

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