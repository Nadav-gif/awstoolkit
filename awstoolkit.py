from parameter_builder import get_parameters, module_parameters_validator
from authenticator import authenticate
from module_runner import run_module

parameters = get_parameters()
sessions = authenticate(profile=parameters.profile, access_key=parameters.access_key, secret_key=parameters.secret_key,
                       session_token=parameters.session_token, role_arn=parameters.role_arn, include_scp=parameters.include_scp)

module_parameters_validator(sessions[0], parameters)
run_module(sessions, parameters)