from modules.get_identity_by_action import get_identity_by_action


def run_module(session, parameters):
    if parameters.module == "get_identity_by_action":
        get_identity_by_action(session, parameters.action)
