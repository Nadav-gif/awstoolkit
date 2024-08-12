from modules import *
import boto3

def authenticate(**kwargs):
    if kwargs["profile"]:
        # shows current user
        session = boto3.Session(profile_name=kwargs["profile"])
        client = session.client("sts")  # sts for temporary identification
        response = client.get_caller_identity()
        #print(response)
    elif kwargs["access_key"] and kwargs["secret_key"]:
        if kwargs["session_token"]:
            session = boto3.Session(aws_access_key_id=kwargs['access_key'],
                                    aws_secret_access_key=kwargs['secret_key'],
                                    aws_session_token=kwargs['session_token'])
        else:
            session = boto3.Session(aws_access_key_id=kwargs['access_key'],
                                    aws_secret_access_key=kwargs['secret_key'])
        client = session.client("sts")
        #response = client.get_caller_identity()


    if kwargs["role_arn"]:
        session = role_to_assume(client=client, role_arn=kwargs["role_arn"])

    return session

#gives keys to use the role
def role_to_assume(client, role_arn):
    response = client.assume_role(RoleArn=role_arn, RoleSessionName="aws_toolkit")
    session = boto3.Session(aws_access_key_id=response['Credentials']['AccessKeyId'],
                            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                            aws_session_token=response['Credentials']['SessionToken'])
    return session

