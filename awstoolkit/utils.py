import re
from awstoolkit.all_actions_list import get_all_actions


def get_managed_policy_content(client, policy_arn):
    # Get a policy_arn and return a list of its statements.
    # This work for now only for managed policy because we get ARN (inline doesn't have ARN). Need to make more generic.
    policy_details = client.get_policy(PolicyArn=policy_arn)
    default_version_id = policy_details["Policy"]["DefaultVersionId"]
    policy_content = client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
    policy_statement = policy_content["PolicyVersion"]["Document"]["Statement"]
    return policy_statement


def get_inline_policy_content(client, identity_name, identity_type, policy_name):
    # Get inline policy identifiers and return the content
    if identity_type == "User":
        policy_content = client.get_user_policy(PolicyName=policy_name, UserName=identity_name)
    elif identity_type == "Role":
        policy_content = client.get_role_policy(PolicyName=policy_name, RoleName=identity_name)
    elif identity_type == "Group":
        policy_content = client.get_group_policy(PolicyName=policy_name, GroupName=identity_name)

        client.get_group_policy(PolicyName=policy_name, GroupName=identity_name)

    else:
        print("Error getting inline policy, quiting")
        exit()
    policy_statement = policy_content["PolicyDocument"]["Statement"]
    return policy_statement


def statement_parser(statement, identity_allow_list, identity_deny_list):
    # Function gets a policy statement and parse it to split the content between the allow and deny list.
    if statement.get("Action"):
        statement_actions = [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        if statement["Effect"] == "Allow":
            for action in statement_actions:
                identity_allow_list.append({"action": action, "resource": statement["Resource"]})
        if statement["Effect"] == "Deny":
            for action in statement_actions:
                identity_deny_list.append({"action": action, "resource": statement["Resource"]})

    elif statement.get("NotAction"):
        statement_notactions = [statement["NotAction"]] if isinstance(statement["NotAction"], str) else statement["NotAction"]
        all_actions = get_all_actions()
        if statement["Effect"] == "Allow":
            for action in all_actions:
                is_in_not_action = False
                for not_action in statement_notactions:
                    if re.search(not_action.lower().replace("*", ".*"), action.lower()):
                        is_in_not_action = True
                if not is_in_not_action:
                    identity_allow_list.append({"action": action, "resource": statement["Resource"]})
        if statement["Effect"] == "Deny":
            for action in all_actions:
                is_in_not_action = False
                for not_action in statement_notactions:
                    if re.search(not_action.lower().replace("*", ".*"), action.lower()):
                        is_in_not_action = True
                if not is_in_not_action:
                    identity_deny_list.append({"action": action, "resource": statement["Resource"]})

    return identity_allow_list, identity_deny_list


def get_affected_resources(action_parameter, identity_actions_list):
    # Get the action parameter and the actions list in format [{'action': 'a4b:Get*', 'resource': '*'}], and return a list of the affected resources.
    affected_resources = []
    for policy_action in identity_actions_list:
        if re.search(policy_action["action"].lower().replace("*", ".*"), action_parameter.lower()):
            affected_resources.append(policy_action["resource"])
            if policy_action["resource"] == "*" or policy_action["resource"] == ["*"]:
                affected_resources = ["*"]
                break
    flattened_resources = [item for sublist in affected_resources for item in  # get rid of duplicates in the resource list.
                           (sublist if isinstance(sublist, list) else [sublist])]
    return list(set(flattened_resources))


def policy_intersection_resources(wider_action, thinner_action):
    # Gets two actions and their resources compares two actions and returns the resources that are contained in both
    # For example, if the attached policies give an identity ec2:startInstances on instances t*, and the permission boundary limit it to test, the result will be "test".
    final_resource_list = []
    calculated_allow_list = []

    for resource in wider_action["resource"]:
        for boundary_resource in thinner_action["resource"]:
            if re.search(boundary_resource.replace("*", ".*"), resource):
                final_resource_list.append(resource)
            elif re.search(resource.replace("*", ".*"), boundary_resource):
                final_resource_list.append(boundary_resource)
    calculated_allow_list.append(
        {"action": wider_action["action"], "resource": final_resource_list})  # The final action is the one from allow list

    return calculated_allow_list


def get_policies_intersection(actions_list, restricted_list):
    # Get two lists of the format [{'action': 'a4b:Get*', 'resource': '*'}], and return the intersection between them
    # This is useful to bring an allow_list from identities' policies and a list of the permission limiter (like SCP, or Permission Boundary). and get the actual permissions.
    calculated_allow_list = []
    for action in actions_list:
        for boundary_action in restricted_list:

            if re.search(boundary_action["action"].replace("*", ".*"), action["action"]):  # The Allow list action is contained in the PB (PB is bigger)
                calculated_allow_list += policy_intersection_resources(action, boundary_action)

            if re.search(action["action"].replace("*", ".*"), boundary_action["action"]):  # The PB action is contained in the Allow List (AL is bigger)
                calculated_allow_list += policy_intersection_resources(boundary_action, action)

    return calculated_allow_list


def remove_dict_duplicates(dict_list):
    # Get a list of dictionaries and remove duplicates
    unique_list = []
    for d in dict_list:
        if d not in unique_list:
            unique_list.append(d)
    return unique_list
