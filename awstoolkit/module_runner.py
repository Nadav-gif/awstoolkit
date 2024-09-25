from who_can import who_can_execute
from can_do import can_do_execute
from policy_diff import policy_diff_execute


def run_module(sessions, parameters):
    if parameters.module == "who-can":
        who_can_execute(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.output_format)
    if parameters.module == "can-do":
        can_do_execute(sessions, parameters.action, parameters.include_scp, parameters.output, parameters.identity)
    if parameters.module == "policy-diff":
        policy_diff_execute(sessions, parameters.output_format, parameters.output, parameters.policy_a, parameters.policy_b)

