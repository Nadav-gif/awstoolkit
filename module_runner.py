from modules.who_can import who_can


def run_module(sessions, parameters):
    if parameters.module == "who-can":
        who_can(sessions, parameters.action, parameters.include_scp)
