from modules.who_can import who_can


def run_module(session, parameters):
    if parameters.module == "who-can":
        who_can(session, parameters.action)
