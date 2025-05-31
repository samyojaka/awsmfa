import boto3
import sys
from botocore.session import Session as BotocoreSession
import os
import configparser

AWS_CONFIG_PATH = os.path.expanduser("~/.aws/config")

def save_to_aws_config(profile, region, serial_number):
    config = configparser.ConfigParser()
    config.read(AWS_CONFIG_PATH)

    # AWS config uses 'profile <name>' except for 'default'
    section = f"profile {profile}" if profile != "default" else "default"
    if not config.has_section(section):
        config.add_section(section)

    if region:
        config.set(section, "region", region)
    if serial_number:
        config.set(section, "mfa_serial", serial_number)

    with open(AWS_CONFIG_PATH, "w") as configfile:
        config.write(configfile)
    print(f"Saved region and MFA serial to [{section}] in {AWS_CONFIG_PATH}")

def get_session_token_with_mfa(mfa_serial_number, mfa_token_code, region_name, profile_name, duration_seconds=3600):
    """
    Generate AWS STS session token using MFA, specifying region and profile.
    """
    session = boto3.Session(profile_name=profile_name, region_name=region_name)
    sts_client = session.client('sts')
    response = sts_client.get_session_token(
        SerialNumber=mfa_serial_number,
        TokenCode=mfa_token_code,
        DurationSeconds=duration_seconds
    )
    credentials = response['Credentials']
    print("AccessKeyId:", credentials['AccessKeyId'])
    print("SecretAccessKey:", credentials['SecretAccessKey'])
    print("SessionToken:", credentials['SessionToken'])
    print("Expiration:", credentials['Expiration'])
    return credentials

if __name__ == "__main__":
    # List available profiles
    available_profiles = boto3.session.Session().available_profiles

    profile = input("Enter preferred awscli profile: ")
    if profile not in available_profiles:
        print(f"Profile '{profile}' not found. Available profiles: {', '.join(available_profiles)}")
        sys.exit(1)

    # Get region from profile config
    boto3_session = boto3.Session(profile_name=profile)
    region = boto3_session.region_name
    if not region:
        region = input("Enter preferred region: ")

    # Get MFA serial from profile config
    botocore_session = BotocoreSession(profile=profile)
    config = botocore_session.get_scoped_config()
    serial_number = config.get('mfa_serial', None)
    if not serial_number:
        serial_number = input("Enter current MFA arn: ")

    # Save region and serial_number if they were missing and provided by user
    save_to_aws_config(profile, region, serial_number)

    token_code = input("Enter current MFA code: ")
    get_session_token_with_mfa(serial_number, token_code, region, profile)
