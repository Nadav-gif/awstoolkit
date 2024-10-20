from awstoolkit.utils import get_managed_policy_content, statement_parser, get_policies_intersection, remove_dict_duplicates
from awstoolkit.authenticator import authenticate
import csv


def create_policy_allow_deny_lists(client, policy_arn):
    # Function gets an identity from identity list and return two lists:
    # Allow list -> The list contains all allow actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]
    # Deny list -> The list contains all deny actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]

    policy_allow_list, policy_deny_list = [], []
    policy_statements = get_managed_policy_content(client, policy_arn)
    for statement in policy_statements:
        policy_allow_list, policy_deny_list = statement_parser(statement, policy_allow_list, policy_deny_list)

    return policy_allow_list, policy_deny_list


def join_allow_list(allow_list):
    # Reunite resources of the same action in the allow list.
    # e.g  For the input [{"action": "ec2:StartInstances", "resource": "ec2_instance-arn-A"}, {"action": "ec2:StartInstances", "resource": "ec2_instance-arn-B"}]
    # The output is [{"action": "ec2:StartInstances", "resource": "['ec2_instance-arn-A', 'ec2_instance-arn-B']"}]
    joined = {}

    for item in allow_list:
        action = item['action']
        resource = item['resource']
        if action not in joined:
            joined[action] = {'action': action, 'resource': []}
        if isinstance(joined[action]['resource'], list):
            joined[action]['resource'].append(resource)
        else:
            joined[action]['resource'] = [joined[action]['resource'], resource]
    return list(joined.values())


def split_action_list(allow_list):
    # Gets an action list and split it so each resource will have a seperate dictionary in the list.
    # e.g  For the input [{"action": "ec2:StartInstances", "resource": "['ec2_instance-arn-A', 'ec2_instance-arn-B']"}]
    # The output is [{"action": "ec2:StartInstances", "resource": "ec2_instance-arn-A"}, {"action": "ec2:StartInstances", "resource": "ec2_instance-arn-B"}]
    split_allow_list = []
    for action_resource in allow_list:
        if isinstance(action_resource['resource'], list):
            for resource in action_resource['resource']:
                split_allow_list.append({'action': action_resource['action'], 'resource': resource})
        else:
            split_allow_list.append(action_resource)
    return split_allow_list


def final_allow_list_generate(allow_list, intersection):
    # Gets an allow list and the intersection between the two policies, and return only the actions and relevant resources that exist only in the given allow list
    # We use it to differentiate between actions (and relevant resources) that exist in both policies to actions that exist in one policy.
    split_allow_list = split_action_list(allow_list)
    split_intersection = split_action_list(intersection)
    final_allow_list = []
    for action in split_allow_list:
        if action not in split_intersection:
            final_allow_list.append(action)

    return final_allow_list


def generate_output_for_csv(allow_list, deny_list, writer):
    # Generates output for the given allow list and deny list
    writer.writerow(["Action Name", "Allow on", "Deny on"])
    for action in allow_list:
        deny_resources = []
        for deny_action in deny_list:
            if action['action'] == deny_action['action']:
                deny_resources.append(deny_action['resource'])
        writer.writerow([action['action'], action['resource'], str(deny_resources)])
    writer.writerow(['\n'])


def get_policy_exist(client, policy_arn):
    # Verify that a policy with the given policy_arn exist
    try:
        client.get_policy(policy_arn)
    except:
        print(f"Policy {policy_arn} does not exist")
        exit()


def policy_diff_execute(sessions, output_format, output_path, policy_a, policy_b):  #ARN's
    iam_client = sessions[0].client("iam")
    get_policy_exist(iam_client, policy_a)
    get_policy_exist(iam_client, policy_b)
    policy_a_allow_list, policy_a_deny_list = create_policy_allow_deny_lists(iam_client, policy_a)
    policy_b_allow_list, policy_b_deny_list = create_policy_allow_deny_lists(iam_client, policy_b)
    intersection = get_policies_intersection(policy_a_allow_list, policy_b_allow_list)
    intersection = remove_dict_duplicates(intersection)

    final_policy_a_allow_list = join_allow_list(final_allow_list_generate(policy_a_allow_list, intersection))
    final_policy_b_allow_list = join_allow_list(final_allow_list_generate(policy_b_allow_list, intersection))

    output_filepath = f"{output_path}/policy_diff.csv"
    if output_format == 'csv':
        with open(output_filepath, "w", newline="") as output_file:
            writer = csv.writer(output_file)
            writer.writerow([f"{policy_a}"])
            generate_output_for_csv(final_policy_a_allow_list, policy_a_deny_list, writer)
            writer.writerow([f"{policy_b}"])
            generate_output_for_csv(final_policy_b_allow_list, policy_b_deny_list, writer)
            writer.writerow(["Shared"])
            writer.writerow(["Action Name", "Allow on"])
            for action in intersection:
                writer.writerow([action['action'], action['resource']])

    if output_format == 'json':
        final_output = {'policy_a': {'arn': policy_a, 'allowed_actions': final_policy_a_allow_list, 'deny_actions': policy_a_deny_list},
                        'policy_b': {'arn': policy_b, 'allowed_actions': final_policy_b_allow_list, 'deny_actions': policy_b_deny_list},
                        'shared': intersection}

        return {'output': final_output}


def policy_diff(**kwargs):
    sessions = authenticate(profile=kwargs.get("profile"),
                            access_key=kwargs.get("access_key"),
                            secret_key=kwargs.get("secret_key"),
                            session_token=kwargs.get("session_token"),
                            role_arn=kwargs.get("role_arn"))

    return policy_diff_execute(sessions,
                               output_format="json",
                               output_path="",
                               policy_a=kwargs.get("p1"),
                               policy_b=kwargs.get("p2"))
