# IAM Access Key Rotator

Automated Python solution to detect and rotate stale AWS IAM access keys (older than 90 days). New keys are stored securely in AWS Secrets Manager. Designed to be **idempotent** — safe to run multiple times or on a schedule.

---

## How it works

```
For every IAM user
  → List their access keys
  → If a key is older than 90 days:
      1. Check idempotency (already rotated in a prior run?)
      2. Create a new IAM access key
      3. Store the new key in Secrets Manager
      4. Deactivate the old key
      5. Delete the old key
```

---

## Project structure

```
iam-key-rotator/
├── rotate_iam_keys.py      # Main rotation script
├── test_rotate_iam_keys.py # Unit tests (34 cases, fully mocked)
└── README.md
```

---

## Requirements

- Python 3.10+
- `boto3` (`pip install boto3`)
- AWS credentials configured (env vars, `~/.aws/credentials`, or IAM role)

---

## IAM permissions needed

The IAM principal running this script requires:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:ListUsers",
    "iam:ListAccessKeys",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "iam:DeleteAccessKey",
    "secretsmanager:DescribeSecret",
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue",
    "secretsmanager:GetSecretValue"
  ],
  "Resource": "*"
}
```

---

## Usage

### Dry run (preview only — no changes made)
```bash
python rotate_iam_keys.py --dry-run
```

### Rotate all stale keys
```bash
python rotate_iam_keys.py
```

### Rotate a specific user only
```bash
python rotate_iam_keys.py --username alice
```

### Custom threshold and region
```bash
python rotate_iam_keys.py --max-age-days 60 --region eu-west-1
```

### All options
```
--region         AWS region (default: us-east-1)
--max-age-days   Rotate keys older than N days (default: 90)
--dry-run        Preview only, no changes
--username       Limit to one IAM user
```

---

## Where new keys are stored

Each user's current key is stored in Secrets Manager at:

```
iam/access-keys/<username>
```

Secret value (JSON):
```json
{
  "username": "alice",
  "access_key_id": "AKIA...",
  "secret_access_key": "...",
  "rotated_at": "2025-06-13T10:00:00+00:00",
  "replaced_key_id": "AKIA_OLD..."
}
```

---

## Idempotency

The script is safe to run multiple times because:

1. **Idempotency guard**: before rotating, it checks whether the existing Secrets Manager secret already references a *different* (newer) key ID. If so, the old key was already replaced in a prior run — it skips rotation.
2. **Secrets Manager upsert**: uses `CreateSecret` on first run, `PutSecretValue` on subsequent runs — never creates duplicate secrets.
3. **AWS key limit guard**: IAM allows max 2 access keys per user. The script checks the count before creating a new one and skips if the user is already at the limit.

---

## Running the tests

No real AWS account needed — all AWS calls are mocked.

```bash
pip install boto3 pytest
pytest test_rotate_iam_keys.py -v
```

34 tests covering:
- Key age detection and staleness logic
- IAM pagination handling
- Secrets Manager create vs. update path
- Idempotency guard (already-rotated detection)
- Dry-run mode
- AWS key count limit enforcement
- Error isolation (one user's failure doesn't stop the rest)

---

## Scheduling (recommended)

Run daily via **AWS EventBridge + Lambda** or a cron job:

```
0 6 * * * python /opt/scripts/rotate_iam_keys.py >> /var/log/iam-rotation.log 2>&1
```

Or wrap in a Lambda function and trigger with an EventBridge rule:
```
rate(1 day)
```

---

## Design decisions

| Decision | Rationale |
|---|---|
| Deactivate before delete | If delete fails mid-run, old key is already disabled — safe on retry |
| Store key *before* deactivation | On failure, we can always retrieve the new key |
| Secret path `iam/access-keys/<user>` | Predictable, one secret per user — no unbounded growth |
| `was_already_rotated()` check | Prevents double-rotation when script is re-run same day |
| Per-user error isolation | One problematic user doesn't abort the whole run |