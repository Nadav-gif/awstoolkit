from modules import *
import boto3

def authenticate(**kwargs):
    if kwargs["profile"]:
        # shows current user
        session = boto3.Session(profile_name=kwargs["profile"])
        check_session_validity(session)
    elif kwargs["access_key"] and kwargs["secret_key"]:
        if kwargs["session_token"]:
            session = boto3.Session(aws_access_key_id=kwargs['access_key'],
                                    aws_secret_access_key=kwargs['secret_key'],
                                    aws_session_token=kwargs['session_token'])
        else:
            session = boto3.Session(aws_access_key_id=kwargs['access_key'],
                                    aws_secret_access_key=kwargs['secret_key'])
        check_session_validity(session)
    else:
        print("Enter a valid authentication method, either access keys or a profile")
        exit()

    if kwargs["role_arn"]:
        session = role_to_assume(session=session, role_arn=kwargs["role_arn"])

    return session


# Gives keys to use the role
def role_to_assume(session, role_arn):
    try:
        client = session.client("sts")
        response = client.assume_role(RoleArn=role_arn, RoleSessionName="aws_toolkit")
        session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                aws_session_token=response['Credentials']['SessionToken'])
        client = session.client("sts")
        response = client.get_caller_identity()
    except Exception as e:
        print("Failed to assume role - Check role ARN and policies")
        exit()

    return session
def check_session_validity(session):
    try:
        client = session.client("sts")  # sts for temporary identification
        response = client.get_caller_identity()
    except:
        print("Authentication failed, existing")
        exit()