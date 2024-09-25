import boto3


def authenticate(**kwargs):
    if kwargs.get("profile"):
        # shows current user
        session = boto3.Session(profile_name=kwargs.get("profile"))
        check_session_validity(session)
    elif kwargs.get("access_key") and kwargs.get("secret_key"):
        if kwargs.get("session_token"):
            session = boto3.Session(aws_access_key_id=kwargs.get('access_key'),
                                    aws_secret_access_key=kwargs.get('secret_key'),
                                    aws_session_token=kwargs.get('session_token'))
        else:
            session = boto3.Session(aws_access_key_id=kwargs.get('access_key'),
                                    aws_secret_access_key=kwargs.get('secret_key'))
        check_session_validity(session)
    else:
        print("Enter a valid authentication method, either access keys or a profile")
        exit()

    management_session = session

    if kwargs.get("role_arn"):
        session = role_to_assume(session=session, role_arn=kwargs.get("role_arn"))

    return session, management_session


# Gives keys to use the role
def role_to_assume(session, role_arn):
    try:
        client = session.client("sts")
        response = client.assume_role(RoleArn=role_arn, RoleSessionName="aws_toolkit")
        session = boto3.Session(aws_access_key_id=response.get('Credentials').get('AccessKeyId'),
                                aws_secret_access_key=response.get('Credentials').get('SecretAccessKey'),
                                aws_session_token=response.get('Credentials').get('SessionToken'))
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