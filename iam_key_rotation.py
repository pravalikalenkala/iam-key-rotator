"""
IAM Access Key Rotation
=======================
Detects AWS IAM access keys older than 90 days, rotates them,
and stores the new credentials in Secrets Manager.

Usage:
    pip install boto3
    python iam_key_rotation.py [--dry-run] [--max-age-days 90]
"""

import boto3
import json
import logging
import argparse
from datetime import datetime, timezone

logging.basicConfig(format="%(levelname)s  %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

iam = boto3.client("iam")
sm  = boto3.client("secretsmanager")


def get_stale_keys(max_age_days):
    """Return list of (username, key_id, age_days) for Active keys older than max_age_days."""
    stale = []
    for user in iam.list_users()["Users"]:
        name = user["UserName"]
        for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if key["Status"] == "Active" and age >= max_age_days:
                stale.append((name, key["AccessKeyId"], age))
    return stale


def already_rotated(username, old_key_id):
    """Return True if Secrets Manager already has a new key recorded for this old key."""
    try:
        data = json.loads(sm.get_secret_value(SecretId=f"iam/{username}/{old_key_id}")["SecretString"])
        return data.get("access_key_id") != old_key_id
    except sm.exceptions.ResourceNotFoundException:
        return False


def rotate(username, old_key_id, dry_run):
    """Create a new key, store it in Secrets Manager, deactivate the old one."""
    if dry_run:
        log.info("  [DRY-RUN] would rotate %s / %s", username, old_key_id)
        return

    # AWS allows max 2 keys per user
    if len(iam.list_access_keys(UserName=username)["AccessKeyMetadata"]) >= 2:
        log.warning("  SKIP — user already has 2 keys, manual cleanup needed")
        return

    # Create new key
    new_key = iam.create_access_key(UserName=username)["AccessKey"]
    log.info("  Created new key: %s", new_key["AccessKeyId"])

    # Store in Secrets Manager
    secret_name = f"iam/{username}/{old_key_id}"
    payload = json.dumps({
        "username":          username,
        "access_key_id":     new_key["AccessKeyId"],
        "secret_access_key": new_key["SecretAccessKey"],
        "replaced_key_id":   old_key_id,
        "rotated_at":        datetime.now(timezone.utc).isoformat(),
    })
    try:
        sm.put_secret_value(SecretId=secret_name, SecretString=payload)
    except sm.exceptions.ResourceNotFoundException:
        sm.create_secret(Name=secret_name, SecretString=payload)
    log.info("  Stored credentials: %s", secret_name)

    # Deactivate (not delete) the old key — keeps audit trail
    iam.update_access_key(UserName=username, AccessKeyId=old_key_id, Status="Inactive")
    log.info("  Deactivated old key: %s", old_key_id)


def main():
    parser = argparse.ArgumentParser(description="Rotate stale IAM access keys.")
    parser.add_argument("--dry-run", action="store_true", help="Scan only, no changes")
    parser.add_argument("--max-age-days", type=int, default=90, help="Key age threshold (default: 90)")
    args = parser.parse_args()

    log.info("Scanning for keys older than %d days...", args.max_age_days)
    stale = get_stale_keys(args.max_age_days)

    if not stale:
        log.info("No stale keys found.")
        return

    for username, key_id, age in stale:
        log.info("Stale: %s / %s (%d days)", username, key_id, age)

        if already_rotated(username, key_id):
            log.info("  Already rotated — ensuring Inactive")
            if not args.dry_run:
                iam.update_access_key(UserName=username, AccessKeyId=key_id, Status="Inactive")
            continue

        try:
            rotate(username, key_id, args.dry_run)
        except Exception as e:
            log.error("  FAILED: %s", e)

    log.info("Done.")


if __name__ == "__main__":
    main()