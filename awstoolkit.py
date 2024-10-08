from awstoolkit.parameter_builder import get_parameters, module_parameters_validator
from awstoolkit.authenticator import authenticate
from awstoolkit.module_runner import run_module

if __name__ == '__main__':  # Learn
    parameters = get_parameters()
    sessions = authenticate(profile=parameters.profile, access_key=parameters.access_key, secret_key=parameters.secret_key,
                            session_token=parameters.session_token, role_arn=parameters.role_arn, include_scp=parameters.include_scp)  # when using scp identify as management account to have access to scp policy

    module_parameters_validator(sessions[0], parameters)  # returns if the action exists or not
    run_module(sessions, parameters)  # gets the session and the module
