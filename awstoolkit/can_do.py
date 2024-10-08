from awstoolkit.who_can import who_can_execute
from awstoolkit.authenticator import authenticate
from awstoolkit.parameter_builder import action_parameter_validator


def can_do_execute(sessions, action_parameter, include_scp, identity_can_do):  # this module only outputs JSON
    who_can_output = who_can_execute(sessions, action_parameter, include_scp, "", "json")

    for identity in who_can_output["output"]:
        if identity["Arn"] == identity_can_do:
            return identity

    return False


def can_do(**kwargs):
    sessions = authenticate(profile=kwargs.get("profile"),
                            access_key=kwargs.get("access_key"),
                            secret_key=kwargs.get("secret_key"),
                            session_token=kwargs.get("session_token"),
                            role_arn=kwargs.get("role_arn"))
    action_parameter_validator(sessions[0], kwargs.get("action"))  # returns if the action exists or not
    return can_do_execute(sessions,
                          action_parameter=kwargs.get("action"),
                          include_scp=kwargs.get("include_scp"),
                          identity_can_do=kwargs.get("identity"))


