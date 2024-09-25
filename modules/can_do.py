from .who_can import who_can


def can_do(sessions, action_parameter, include_scp, output_path, identity_can_do):
    who_can_output = who_can(sessions, action_parameter, include_scp, output_path, "json", identity_can_do)

    for identity in who_can_output["output"]:
        if identity["Arn"] == identity_can_do:
            return identity

    return False
