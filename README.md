![image](https://github.com/user-attachments/assets/fba4541d-bc01-4791-9d63-7c7a561ad3c8)# aws-mfa (mfa.py)

Prerequisites
This script is built on python on version 3.12.3

Following libraries are required to be pre-installed via pip before running this command.
boto3==1.38.28
botocore==1.38.28
pytz==2025.2


# Info steps:

This script tool is based on python which allows our aws iam user to connect to ec2 instance nodes with temporary api keys only if created with mfa set user's iam profile. This script fetches available details ~/.aws/credentails & ~/.aws/config from local machine and runs asks for input based on availble details.


The current info in aws config & credentials only contains basic information required by awscli.
![alt text](image.png)

When running the script with # python3 mfa.py. Script will analyse current info in the local files and ask for input accordingly.
![alt text](image-1.png)
Once all corect input is provided, script will save temporary credentials in credentials file and mfa_serial in config file which can be checked in file.

Original credentials are stored in [{profile}::source-profile] & temporary credentials stored in [{profile}].
![alt text](image-3.png)


When the temporary credentials are expired and user wants to generate new credentials, just run the script again with [python3 mfa.py]. This script will autmatically replace old credentials with new one.
![alt text](image-4.png).


Note: Run this script from same directory where script is there or give full path of script.
