import boto3
import sys
import argparse
from datetime import datetime
import pytz
from botocore.session import Session as BotocoreSession
import os
import configparser
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound, NoRegionError, ParamValidationError

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")
AWS_CREDENTIALS_PATH = os.path.expanduser("~/.aws/credentials")

def save_to_aws_config(profile, region, serial_number):
    config = configparser.ConfigParser()
    try:
        config.read(AWS_CONFIG_PATH)
        section = f"profile {profile}" if profile != "default" else "default"
        updated = False

        if not config.has_section(section):
            config.add_section(section)
            updated = True

        if region and config.get(section, "region", fallback=None) != region:
            config.set(section, "region", region)
            updated = True
        if serial_number and config.get(section, "mfa_serial", fallback=None) != serial_number:
            config.set(section, "mfa_serial", serial_number)
            updated = True

        if updated:
            with open(AWS_CONFIG_PATH, "w") as configfile:
                config.write(configfile)
            print(f"Saved region and MFA serial to [{section}] in {AWS_CONFIG_PATH}")
    except (IOError, OSError) as e:
        print(f"Error writing to AWS config file: {e}")
    except Exception as e:
        print(f"Unexpected error while saving AWS config: {e}")

def save_to_aws_credentials(profile, access_key, secret_key, session_token):
    """
    Save temporary session credentials to the AWS credentials file under the given profile.
    Archive permanent credentials under [{profile}::source-profile] ONLY IF NOT ALREADY PRESENT.
    """
    credentials = configparser.ConfigParser()
    credentials.read(AWS_CREDENTIALS_PATH)
    section = profile if profile != "default" else "default"
    archive_section = f"{profile}::source-profile"

    # Archive permanent credentials only if archive section does not already exist
    if not credentials.has_section(archive_section):
        if credentials.has_section(section):
            old_access_key = credentials.get(section, "aws_access_key_id", fallback=None)
            old_secret_key = credentials.get(section, "aws_secret_access_key", fallback=None)
            # Only archive if both keys are present and not session credentials
            if old_access_key and old_secret_key:
                credentials.add_section(archive_section)
                credentials.set(archive_section, "aws_access_key_id", old_access_key)
                credentials.set(archive_section, "aws_secret_access_key", old_secret_key)
                print(f"Archived permanent credentials to [{archive_section}] in {AWS_CREDENTIALS_PATH}")

    # Write new session credentials to the main profile
    if not credentials.has_section(section):
        credentials.add_section(section)
    credentials.set(section, "aws_access_key_id", access_key)
    credentials.set(section, "aws_secret_access_key", secret_key)
    credentials.set(section, "aws_session_token", session_token)

    with open(AWS_CREDENTIALS_PATH, "w") as credfile:
        credentials.write(credfile)
    print(f"Saved session credentials to [{section}] in {AWS_CREDENTIALS_PATH}")


def get_permanent_credentials_from_archive(profile):
    """
    Load permanent credentials from [{profile}::source-profile] in the credentials file.
    Returns (access_key, secret_key) or (None, None) if not found.
    """
    credentials = configparser.ConfigParser()
    credentials.read(AWS_CREDENTIALS_PATH)
    archive_section = f"{profile}::source-profile"
    if credentials.has_section(archive_section):
        access_key = credentials.get(archive_section, "aws_access_key_id", fallback=None)
        secret_key = credentials.get(archive_section, "aws_secret_access_key", fallback=None)
        if access_key and secret_key:
            return access_key, secret_key
    return None, None

def get_session_token_with_mfa(mfa_serial_number, mfa_token_code, region_name, profile_name, duration_seconds=3600):
    """
    Generate AWS STS session token using MFA, specifying region and profile.
    Uses permanent credentials from [{profile_name}::source-profile] if present.
    """
    try:
        # Try to load permanent credentials from archive
        access_key, secret_key = get_permanent_credentials_from_archive(profile_name)
        if access_key and secret_key:
            # Use explicit credentials with boto3
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region_name
            )
        else:
            # Fallback to profile credentials
            session = boto3.Session(profile_name=profile_name, region_name=region_name)

        sts_client = session.client('sts')
        response = sts_client.get_session_token(
            SerialNumber=mfa_serial_number,
            TokenCode=mfa_token_code,
            DurationSeconds=duration_seconds
        )
        credentials = response['Credentials']
        utc_expiration = datetime.strptime(str(credentials['Expiration']), "%Y-%m-%d %H:%M:%S%z")
        # Convert UTC time to IST
        ist_expiration = utc_expiration.astimezone(pytz.timezone('Asia/Kolkata'))

        # Format the IST time string
        ist_expiration_str = ist_expiration.strftime('%Y-%m-%d %H:%M:%S %Z')
        # print("AccessKeyId:", credentials['AccessKeyId'])
        # print("SecretAccessKey:", credentials['SecretAccessKey'])
        # print("SessionToken:", credentials['SessionToken'])
        print("Expiration:", ist_expiration_str)
        # Save credentials to file
        save_to_aws_credentials(
            profile_name,
            credentials['AccessKeyId'],
            credentials['SecretAccessKey'],
            credentials['SessionToken']
        )
        return credentials
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"{error_code} - {error_message}")
        sys.exit(2)
    except NoCredentialsError:
        print("No AWS credentials found for the specified profile.")
        sys.exit(2)
    except ParamValidationError as e:
        print(f"Parameter validation error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"Unexpected error while getting session token: {e}")
        sys.exit(2)

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Get AWS session token with MFA.")
        parser.add_argument(
            "--duration",
            type=int,
            default=129600,
            help="Session duration in seconds (min. value 900 max. value 129600, default: 129600)"
        )
        args = parser.parse_args()
        duration_seconds = args.duration

        available_profiles = boto3.session.Session().available_profiles

        profile = input("Enter preferred awscli profile (leave blank for 'default'): ").strip()
        if not profile:
            profile = "default"

        if profile not in available_profiles and profile != "default":
            print(f"Profile '{profile}' not found. Available profiles: {', '.join(available_profiles)}")
            sys.exit(1)

        try:
            boto3_session = boto3.Session(profile_name=profile)
            region = boto3_session.region_name
        except ProfileNotFound:
            print(f"Profile '{profile}' not found in AWS config.")
            sys.exit(1)
        except NoRegionError:
            region = None

        region_missing = not region
        if region_missing:
            region = input("Enter preferred region: ").strip()

        botocore_session = BotocoreSession(profile=profile)
        config = botocore_session.get_scoped_config()
        serial_number = config.get('mfa_serial', None)
        serial_missing = not serial_number
        if serial_missing:
            serial_number = input("Enter current MFA arn: ").strip()

        if region_missing or serial_missing:
            save_to_aws_config(profile, region, serial_number)

        token_code = input("Enter current MFA code: ").strip()
        get_session_token_with_mfa(
            serial_number,
            token_code,
            region,
            profile,
            duration_seconds=duration_seconds
        )

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)