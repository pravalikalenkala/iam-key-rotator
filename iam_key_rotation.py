"""
IAM Access Key Rotation
=======================
Detects IAM access keys older than 90 days, rotates them,
and stores credentials in Secrets Manager.
"""

import boto3
import json
import logging
import argparse
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logging.basicConfig(format="%(levelname)s  %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

iam = boto3.client("iam")
sm = boto3.client("secretsmanager")


def get_stale_keys(max_age_days):
    stale = []
    
    for user in iam.list_users()["Users"]:
            name = user["UserName"]

            keys = iam.list_access_keys(UserName=name)["AccessKeyMetadata"]

            for key in keys:
                age = (datetime.now(timezone.utc) - key["CreateDate"]).days

                if key["Status"] == "Active" and age >= max_age_days:
                    stale.append((name, key["AccessKeyId"], age))

    return stale


def already_rotated(username, old_key_id):
    """
    Check if this key was already processed.
    We still keep this for idempotency safety.
    """
    secret_name = f"iam/{username}/credentials"

    try:
        data = json.loads(
            sm.get_secret_value(SecretId=secret_name)["SecretString"]
        )

        return data.get("replaced_key_id") == old_key_id

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise


def rotate(username, old_key_id, dry_run):
    if dry_run:
        log.info("  [DRY-RUN] would rotate %s / %s", username, old_key_id)
        return

    existing = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    if len(existing) >= 2:
        log.warning("  SKIP — user already has 2 keys")
        return

    # Create new key
    new_key = iam.create_access_key(UserName=username)["AccessKey"]
    log.info("  Created new key: %s", new_key["AccessKeyId"])

    # ✅ SINGLE STABLE SECRET NAME
    secret_name = f"iam/{username}/credentials"

    payload = json.dumps({
        "username": username,
        "access_key_id": new_key["AccessKeyId"],
        "secret_access_key": new_key["SecretAccessKey"],
        "replaced_key_id": old_key_id,
        "rotated_at": datetime.now(timezone.utc).isoformat()
    })

    try:
        # Try update first (normal path)
        sm.put_secret_value(SecretId=secret_name, SecretString=payload)

    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            sm.create_secret(Name=secret_name, SecretString=payload)
        else:
            raise

    log.info("  Stored credentials in: %s", secret_name)

    # Deactivate old key
    iam.update_access_key(
        UserName=username,
        AccessKeyId=old_key_id,
        Status="Inactive"
    )

    log.info("  Deactivated old key: %s", old_key_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-age-days", type=int, default=90)
    args = parser.parse_args()

    log.info("Scanning keys older than %d days...", args.max_age_days)

    stale = get_stale_keys(args.max_age_days)

    if not stale:
        log.info("No stale keys found.")
        return

    for username, key_id, age in stale:
        log.info("Stale: %s / %s (%d days)", username, key_id, age)

        if already_rotated(username, key_id):
            log.info("  Already rotated — skipping")
            continue

        try:
            rotate(username, key_id, args.dry_run)
        except Exception as e:
            log.error("  FAILED: %s", e)

    log.info("Done.")


if __name__ == "__main__":
    main()