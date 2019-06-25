import botocore
import boto3
import datetime
import os

# Inputs from Environment Variables

# Environment Variable: RotationPeriod
# The number of days after which a key should be rotated
rotationPeriod = int(os.environ['RotationPeriod'])

# Environment Variable: RetentionPeriod
# The number of days after rotation to wait before deleting old keys
# Note: This must be less than RotationPeriod
oldKeyRetentionPeriod = int(os.environ['RetentionPeriod'])

# Pre-calculate the rotation and retention cutoff dates
rotationDate = (datetime.datetime.now() - datetime.timedelta(days=rotationPeriod)).date()
retentionDate = (datetime.datetime.now() - datetime.timedelta(days=oldKeyRetentionPeriod)).date()

# Format for lines in credentials.txt
akidLineFormat = 'aws_access_key_id = {}'
secretLineFormat = 'aws_secret_access_key = {}'

# Format for name of ASM secrets
secretNameFormat = 'User_{}_AccessKey'

# IAM Client
iam = boto3.client('iam')

# Secrets Manager Client
sm = boto3.client('secretsmanager')


# Main method for the lambda function
def lambda_handler(event, context):
    users = iam.list_users()
    response = {}

    for user in users['Users']:
        process_user(user, response)

    # Build a response for debugging - doesn't change actual work done, just gives output for testing in Lambda console
    # response = build_response(results)
    response['RotationDate'] = rotationDate.__str__()
    return response


def process_user(user, response):
    """Rotate access keys for a user.

    Inactive keys will be deleted
    Users with no active access keys will not be processed
    Users with no access keys newer than the rotation period will have a new key created and stored in ASM, deleting the oldest key if necessary.
    Users with an access key older than the retention period, but newer than the rotation period will have older keys removed, keeping only the newest key.
    """

    user_name = user['UserName']
    response[user_name] = {}
    lak = iam.list_access_keys(UserName=user_name)

    has_active = False

    # Keys that are older than the rotation cutoff
    old_keys = []

    # Keys that are newer than the rotation cutoff
    new_keys = []

    # Names are hard.
    # Keys that are newer than the rotation cutoff, but have been around long enough that we can delete any old keys.
    # Note that all of these also appear in new_keys. Makes the logic easier
    retention_keys = []

    # Inactive Keys
    inactive_keys = []

    # Creation date of oldest key
    oldest_key = None

    # Classify all access keys for the current user
    for akm in lak['AccessKeyMetadata']:
        if akm['Status'] == 'Active':
            if akm['CreateDate'].date() < rotationDate:
                old_keys.append(akm['AccessKeyId'])
                if oldest_key == None or oldest_key['CreateDate'] > akm['CreateDate']:
                    oldest_key = akm
                if akm['CreateDate'].date() < retentionDate:
                    retention_keys.append(akm['AccessKeyId'])
            else:
                new_keys.append(akm['AccessKeyId'])
        else:
            inactive_keys.append(akm['AccessKeyId'])

    num_old = len(old_keys)
    num_new = len(new_keys)
    num_retention = len(retention_keys)

    # Delete inactive keys
    if len(inactive_keys) > 0:
        response[user_name]["Deleted Inactive Keys"] = []

    for key_to_delete in inactive_keys:
        iam.delete_access_key(UserName=user_name, AccessKeyId=key_to_delete)
        response[user_name]["Deleted Inactive Keys"].append(key_to_delete)

    # Delete oldest key if user has two keys older than the rotation cutoff
    if len(old_keys) > 1 and oldest_key != None:
        iam.delete_access_key(UserName=user_name, AccessKeyId=oldest_key['AccessKeyId'])
        response[user_name]["Deleted Old Key"] = oldest_key['AccessKeyId']

    # If user only has old keys, create a new key and store in ASM
    if num_old > 0 and num_new == 0:
        create_access_key(user, response)
        response[user_name]["Action"] = "Key rotated."
    else:
        response[user_name]["Action"] = "No key rotation required."

    # If user has an old access key, and a key that is older than the retention period, delete the old one
    if num_old == 1 and num_retention == 1:
        for key_to_delete in old_keys:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key_to_delete)
            response[user_name]["Deleted Old Key"] = key_to_delete


def create_access_key(user, response):
    user_name = user['UserName']
    secret_name = secretNameFormat.format(user_name)

    # Create new access key
    new_access_key = iam.create_access_key(UserName=user_name)
    response[user_name]["Created Access Key"] = new_access_key['AccessKey']['AccessKeyId']
    response[user_name]["ASM Secret Name"] = secret_name

    akid_line = akidLineFormat.format(new_access_key['AccessKey']['AccessKeyId'])
    secret_line = secretLineFormat.format(new_access_key['AccessKey']['SecretAccessKey'])
    cred_file_body = '{}\n{}'.format(akid_line, secret_line)

    # Create new secret, or store in existing
    create_secret = False
    try:
        # See if the secret we need already exists
        sm.describe_secret(SecretId=secret_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            create_secret = True
        else:
            raise e  # Go Bonk

    if create_secret:
        sm.create_secret(Name=secret_name, Description='Auto-created secret', SecretString=cred_file_body)
    else:
        sm.put_secret_value(SecretId=secret_name, SecretString=cred_file_body)
