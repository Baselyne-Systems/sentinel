"""
CloudTrail remediators — enable a multi-region trail and enable log validation.

Interface:
    def execute(params: dict, session: boto3.Session) -> dict

Both actions are reversible:
  - enable_trail:          trail can be stopped and deleted
  - enable_log_validation: can be disabled via update_trail(EnableLogFileValidation=False)
"""

from __future__ import annotations


def enable_trail(params: dict, session) -> dict:
    """Create a multi-region CloudTrail trail and start logging.

    Creates a new CloudTrail trail that covers management events across all
    regions and writes logs to the specified (or auto-named) S3 bucket.
    If the trail already exists, starts logging on it.

    Required params:
        account_id: AWS account ID (used to build default trail name/bucket).
        region:     AWS region where the trail is created.
    Optional params:
        trail_name:    Trail name (defaults to ``sentinel-trail``).
        s3_bucket:     S3 bucket for logs (defaults to
                       ``sentinel-cloudtrail-{account_id}``).

    Returns:
        Summary dict with trail_arn and logging_started flag.
    """
    account_id: str = params["account_id"]
    region: str = params["region"]
    trail_name: str = params.get("trail_name", "sentinel-trail")
    s3_bucket: str = params.get("s3_bucket", f"sentinel-cloudtrail-{account_id}")

    ct = session.client("cloudtrail", region_name=region)

    # Check if trail already exists to avoid duplicate-trail errors
    existing_trails = ct.describe_trails(trailNameList=[trail_name], includeShadowTrails=False)
    if existing_trails["trailList"]:
        trail_arn = existing_trails["trailList"][0]["TrailARN"]
    else:
        # Create the S3 bucket first if it doesn't exist
        s3 = session.client("s3", region_name=region)
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=s3_bucket)
            else:
                s3.create_bucket(
                    Bucket=s3_bucket,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
        except s3.exceptions.BucketAlreadyOwnedByYou:
            pass
        except s3.exceptions.BucketAlreadyExists:
            pass

        # Attach a bucket policy allowing CloudTrail to write
        import json
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{s3_bucket}",
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{s3_bucket}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    },
                },
            ],
        }
        s3.put_bucket_policy(Bucket=s3_bucket, Policy=json.dumps(bucket_policy))

        response = ct.create_trail(
            Name=trail_name,
            S3BucketName=s3_bucket,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            IncludeGlobalServiceEvents=True,
        )
        trail_arn = response["TrailARN"]

    ct.start_logging(Name=trail_arn)
    return {"trail_arn": trail_arn, "trail_name": trail_name, "logging_started": True}


def enable_log_validation(params: dict, session) -> dict:
    """Enable CloudTrail log file integrity validation on an existing trail.

    Log file validation uses a digest file mechanism to detect log tampering.
    The trail must already exist.

    Required params:
        trail_name: Name or ARN of the CloudTrail trail.
        region:     AWS region where the trail lives.

    Returns:
        Summary dict with trail_name and log_file_validation_enabled flag.
    """
    trail_name: str = params["trail_name"]
    region: str = params["region"]

    ct = session.client("cloudtrail", region_name=region)
    ct.update_trail(Name=trail_name, EnableLogFileValidation=True)
    return {"trail_name": trail_name, "log_file_validation_enabled": True}
