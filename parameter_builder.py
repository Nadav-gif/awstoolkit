import argparse


def get_parameters():
    parser = argparse.ArgumentParser()

    # Module
    parser.add_argument("module", help="The module you want to run. Options: get-identity-by-action", default="")

    # Authentication arguments
    parser.add_argument("-p", "--profile", help="The name of the profile you want to use", default="")
    parser.add_argument("-ak", "--access_key", help="access key to authenticate aws", default="")
    parser.add_argument("-sk", "--secret_key", help="secret key to authenticate aws", default="")
    parser.add_argument("-st", "--session_token", help="session token", default="")
    parser.add_argument("-r", "--role_arn", help="ARN of role to assume", default="")

    # Modules parameters
    parser.add_argument("-a", "--action", help="Action to check", default="")

    args = parser.parse_args()
    return args
