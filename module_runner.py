from modules.who_can import who_can
from modules.can_do import can_do
from modules.policy_diff import policy_diff


def run_module(sessions, parameters):
    if parameters.module == "who-can":
        who_can(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.output_format)
    if parameters.module == "can-do":
        can_do(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.identity)
    if parameters.module == "policy-diff":
        policy_diff(sessions, parameters.output_format, parameters.output, parameters.policy_a, parameters.policy_b)

