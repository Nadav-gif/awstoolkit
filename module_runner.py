from modules.who_can import who_can
from modules.can_do import can_do


def run_module(sessions, parameters):
    if parameters.module == "who-can":
        who_can(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.identity)
    if parameters.module == "can-do":
        can_do(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.identity)

