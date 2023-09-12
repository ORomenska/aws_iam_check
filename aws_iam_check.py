'''
This script downloads and analyzes AWS IAM Credentials report.
It can be used for montly security review process.
Usage: aws_iam_check.py <action> [-h]

These actions can be chosen:
* view-inactive-users
* block-inactive-users
* view-old-keys

-h Obtain help

Outputs:

Visual representation in form of JSON

Be aware of that AWS allows 1 report creation in 4 hours.
'''

import boto3
import csv
import os
import argparse
from datetime import datetime,timezone

# Function analyzes report file and returns list of inactive user
def check_inactive_users_local(filepath: str) -> list:
    inactivity_days = 45
    datetimenow_now = datetime.now(tz=timezone.utc)
    report_datetime_format = '%Y-%m-%dT%H:%M:%S%z'
    inactive_users = []
    with open(filepath) as iam_report: 
        reader = csv.DictReader(iam_report)
        for user in reader:
            user_info = {}
            accesses = {
                'delta_passwd_usage': None,
                'delta_access_key_1_usage': None,
                'delta_access_key_2_usage': None,
                'delta_user_not_using_passwd': None,
                'delta_user_not_using_access_key_1': None,
                'delta_user_not_using_access_key_2': None
                }
            if user['password_enabled'] == 'true' and user['password_last_used'] not in ['no_information','N/A']:
                user_pswd_last_used = datetime.strptime(user['password_last_used'],report_datetime_format)
                delta_pw = datetimenow_now - user_pswd_last_used
                accesses['delta_passwd_usage'] = delta_pw.days
            if user['password_enabled'] == 'true' and user['password_last_used'] in ['no_information','N/A']:
                user_created = datetime.strptime(user['user_creation_time'],report_datetime_format)
                delta_pw_na = datetimenow_now - user_created
                accesses['delta_user_not_using_passwd'] = delta_pw_na.days
            if user['access_key_1_active'] == 'true' and user['access_key_1_last_used_date'] != 'N/A':
                user_access_key_1_last_used = datetime.strptime(user['access_key_1_last_used_date'],report_datetime_format)
                delta_ak_1 = datetimenow_now - user_access_key_1_last_used
                accesses['delta_access_key_1_usage'] = delta_ak_1.days
            if user['access_key_1_active'] == 'true' and user['access_key_1_last_used_date'] == 'N/A':
                user_created = datetime.strptime(user['user_creation_time'],report_datetime_format)
                delta_ak_1_na = datetimenow_now - user_created
                accesses['delta_user_not_using_access_key_1'] = delta_ak_1_na.days
            if user['access_key_2_active'] == 'true' and user['access_key_2_last_used_date'] != 'N/A':
                user_access_key_2_last_used = datetime.strptime(user['access_key_2_last_used_date'],report_datetime_format)
                delta_ak_2 = datetimenow_now - user_access_key_2_last_used
                accesses['delta_access_key_2_usage'] = delta_ak_2.days
            if user['access_key_2_active'] == 'true' and user['access_key_2_last_used_date'] == 'N/A':
                user_created = datetime.strptime(user['user_creation_time'],report_datetime_format)
                delta_ak_2_na = datetimenow_now - user_created
                accesses['delta_user_not_using_access_key_2'] = delta_ak_2_na.days
           
            if all([value is None for value in accesses.values()]):
                pass          
            elif any([(value is not None) and (value <= inactivity_days) for value in accesses.values()]):
                pass
            else:
                user_info = {'name':user['user'], 'inactivity': str(min(value for value in accesses.values() if (value is not None))) + ' days'}

            if len(user_info) > 0:
                inactive_users.append(user_info)

                
    return inactive_users

# Function checks report for users access keys which need to be rotated
def check_old_access_keys_local(filename: str) -> list:
    rotation_period = 30
    datetimenow_now = datetime.now(tz=timezone.utc)
    report_datetime_format = '%Y-%m-%dT%H:%M:%S%z'
    old_acc_keys_users = []
    with open(filename) as iam_report: 
        reader = csv.DictReader(iam_report)
        for user in reader:
            user_has_old_key = False
            user_info = {
                'name': user['user'],
                'key_1_to_be_rotated': 'N/A',
                'key_2_to_be_rotated': 'N/A'
                }
            accesses_key_1 = {
                'delta_user_last_rotated_access_key_1': None,
                'delta_user_not_rotated_access_key_1': None
                }
            accesses_key_2 = {   
                'delta_user_last_rotated_access_key_2': None,
                'delta_user_not_rotated_access_key_2': None
                }
            # Calculating time deltas for access keys rotation
            if user['access_key_1_active'] == 'true' and user['access_key_1_last_rotated'] != 'N/A':
                user_access_key_1_last_rotated = datetime.strptime(user['access_key_1_last_rotated'],report_datetime_format)
                delta_ak_1 = datetimenow_now - user_access_key_1_last_rotated
                accesses_key_1['delta_user_last_rotated_access_key_1'] = delta_ak_1.days
            if user['access_key_1_active'] == 'true' and user['access_key_1_last_rotated'] == 'N/A':
                user_created = datetime.strptime(user['user_creation_time'],report_datetime_format)
                delta_ak_1_na = datetimenow_now - user_created
                accesses_key_1['delta_user_not_rotated_access_key_1'] = delta_ak_1_na.days
            if user['access_key_2_active'] == 'true' and user['access_key_2_last_rotated'] != 'N/A':
                user_access_key_1_last_rotated = datetime.strptime(user['access_key_2_last_rotated'],report_datetime_format)
                delta_ak_2 = datetimenow_now - user_access_key_2_last_rotated
                accesses_key_2['delta_user_last_rotated_access_key_2'] = delta_ak_2.days
            if user['access_key_2_active'] == 'true' and user['access_key_2_last_rotated'] == 'N/A':
                user_created = datetime.strptime(user['user_creation_time'],report_datetime_format)
                delta_ak_2_na = datetimenow_now - user_created
                accesses_key_2['delta_user_not_rotated_access_key_2'] = delta_ak_2_na.days
            
            
            if any([value for value in accesses_key_1.values() if (value is not None) and (value > rotation_period)]):                    
                    user_info['key_1_to_be_rotated'] = 'YES'
                    user_has_old_key = True

            if any([(value is not None) and (value > rotation_period) for value in accesses_key_2.values()]):
                    user_info['key_2_to_be_rotated'] = 'YES'
                    user_has_old_key = True        
                          
            if user_has_old_key:
                old_acc_keys_users.append(user_info)

    return old_acc_keys_users

# Function blocks Management Console access to user by deleting his/her Login Profile           
def block_console_access(user: str) -> None:

    #Delete Login Profile    
    try:
        client = boto3.client('iam')
        client.delete_login_profile(UserName=user)
    except client.exceptions.NoSuchEntityException as e1:
        print(f'Nothing to do: {e1.response["Error"]["Message"]}')
        return
    except botocore.exceptions.BotoCoreError as e2:
        raise SystemExit(f'Error ocurred during operation: {e2}')
    except Exception as e3:
        raise SystemExit(f'Error ocurred during operation: {e3}')
   
    #Check that profile was deleted
    try:
        client.get_login_profile(UserName=user)
    except client.exceptions.NoSuchEntityException as e1:   
        if 'The user with name' in  e1.response["Error"]["Message"]:
            print('User cannot be found')
        elif 'Login Profile for User' in e1.response["Error"]["Message"]:
            print(f'Console access for user {user} was successfully deactivated')
    except botocore.exceptions.BotoCoreError as e2:
        raise SystemExit(f'Boto3 error occured during console access blocking: {e2}')
    except Exception as e3:
        raise SystemExit(f'Error occured during console access blocking: {e3}')


# Function deactivates user access keys
def deactivate_access_keys(inactive_user: str) -> None:

    try:
        # Deactivate all user access keys
        iam = boto3.resource('iam')
        user = iam.User(inactive_user)
        user_access_keys = user.access_keys  
        for key in user_access_keys.all():            
            key.deactivate()
        # Check that usr access keys were deactivated (because deactivate() method does not provide operation response)
        response = iam.meta.client.list_access_keys(UserName=inactive_user)
        for check_key in response['AccessKeyMetadata']:
            if check_key['Status'] == 'Active':
                raise SystemExit(f'Something went wrong - key with id {check_key["AccessKeyId"]} have not been deactivated')
            if check_key['Status'] == 'Inactive':    
                print(f'{inactive_user}\'s key with id {check_key["AccessKeyId"]} was successfully deactivated')
    except iam.meta.client.exceptions.NoSuchEntityException as e1:
        print(f'No entry was found: {e1}')
    except iam.meta.client.exceptions.ServiceFailureException as e2:
        raise SystemExit(f'Service error occured during key deactivation: {e2}')
    except botocore.exceptions.BotoCoreError as e3:
        raise SystemExit(f'Boto3 error occured during key deactivation: {e3}')
    except Exception as e4:
        raise SystemExit(f'Error occured during key deactivation: {e4}')


# Function prints inactive users
def print_inactive_users_local(filename: str) -> None:

    inactive_users = check_inactive_users_local(filename)
    if len(inactive_users) == 0:
        print("No inactive users found.")
    else:
        for user in inactive_users:
            print(user)

# Function prints old access keys
def print_old_access_keys_local(filename: str) -> None:

    old_access_keys = check_old_access_keys_local(filename)
    for keys in old_access_keys:
        print(keys)

# Function connects to AWS to generate IAM credentials report.
# If there is already generated report within 4 hours, new report would not be generated. 
def generate_aws_report() -> None:
    
    try:
        client = boto3.client('iam')
        response = client.generate_credential_report()
        #print(response)
    except botocore.exceptions.BotoCoreError as e1:
        raise SystemExit(f'Boto3 error occured during report generation: {e1}')
    except Exception as e2:
        raise SysExit(f'Error occured during report generation: {e2}')

# Function connects to AWS to download previously generated IAM credentials report. 
def load_aws_report() -> str:

    filename = 'report-' + datetime.now().strftime('%Y%m%d-%H:%M:%S') + '.csv'
    try:
        client = boto3.client('iam')
        response2 = client.get_credential_report()
    except botocore.exceptions.BotoCoreError as e1:
        raise SystemExit(f'Boto3 error occured during report retrieving: {e1}')
    except Exception as e2:
        raise SysExit(f'Error occured while connecting to service: {e2}')
    with open(filename,'wb') as report_binary:
        report_binary.write(response2['Content'])

    return filename
    

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('action', nargs='?',choices=['view-inactive-users','block-inactive-users','view-old-keys'])
    args = parser.parse_args()
    if args.action:
        if 'view-inactive-users' in args.action:
            generate_aws_report()
            report_file = load_aws_report()
            print_inactive_users_local(report_file)
            if os.path.isfile(report_file):
                try:
                    os.remove(report_file)
                except:
                    raise SystemExit("Could not remove report file")
        if 'view-old-keys' in args.action:
            generate_aws_report()
            report_file = load_aws_report()
            print_old_access_keys_local(report_file)
            if os.path.isfile(report_file):
                try:
                    os.remove(report_file)
                except:
                    raise SystemExit("Could not remove report file")
        if 'block-inactive-users' in args.action:
            generate_aws_report
            report_file = load_aws_report()
            inactive_users_list = check_inactive_users_local(report_file)
            for inactive_user in inactive_users_list:
                block_console_access(inactive_user['name'])
                deactivate_access_keys(inactive_user['name'])
            if os.path.isfile(report_file):
                try:
                    os.remove(report_file)
                except:
                    raise SystemExit("Could not remove report file")




if __name__ == "__main__":
    main()   
        