from .who_can import who_can


def can_do(sessions, action_parameter, include_scp, output_path, identity_can_do):
    who_can(sessions, action_parameter, include_scp, output_path, identity_can_do)
