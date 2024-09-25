from .who_can import who_can_execute
from .authenticator import authenticate


def can_do_execute(sessions, action_parameter, include_scp, output_path, identity_can_do):
    who_can_output = who_can_execute(sessions, action_parameter, include_scp, output_path, "json")

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

    return can_do_execute(sessions,
                          action_parameter=kwargs.get("action"),
                          include_scp=kwargs.get("include_scp"),
                          output_path=kwargs.get("output_path"),
                          identity_can_do=kwargs.get("identity"))


