import argparse


def action_parameter_validator(session, action):
    # Checks if the required action exists
    service, action_method = action.split(":")[0], action.split(":")[1]
    action_client = session.client(service, region_name="us-east-2")
    methods = [method.replace("_", "").lower() for method in dir(action_client) if not method.startswith("_")] # return a list of all callable actions
    action_method = action_method.lower()
    if action_method not in methods:
        print("Please enter a valid action")
        exit()


def module_parameters_validator(session, parameters_from_user):
    # Gets the args from the user, and check validity of each parameter
    if parameters_from_user.action:
        action_parameter_validator(session, parameters_from_user.action)


def get_parameters():
    parser = argparse.ArgumentParser()

    # Module
    parser.add_argument("module", help="The module you want to run. Options: who-can", default="")

    # Authentication arguments
    parser.add_argument("-p", "--profile", help="The name of the profile you want to use", default="")
    parser.add_argument("-ak", "--access_key", help="access key to authenticate aws", default="")
    parser.add_argument("-sk", "--secret_key", help="secret key to authenticate aws", default="")
    parser.add_argument("-st", "--session_token", help="session token", default="")
    parser.add_argument("-r", "--role_arn", help="ARN of role to assume", default="")

    # Modules parameters
    parser.add_argument("-a", "--action", help="Action to check", default="")
    parser.add_argument("-o", "--output", help="Output directory path, if not stated export output to ./output/", default="output")
    parser.add_argument("-scp", "--include_scp", help="Analyze also the scp while calculating permissions.",
                        action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    return args
