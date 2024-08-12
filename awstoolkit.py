from parameter_builder import get_parameters
from authenticator import authenticate
from module_runner import run_module

parameters = get_parameters()
session = authenticate(profile=parameters.profile, access_key=parameters.access_key, secret_key=parameters.secret_key,
                       session_token=parameters.session_token, role_arn=parameters.role_arn)
run_module(session, parameters)