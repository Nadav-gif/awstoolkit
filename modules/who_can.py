import re
import csv


def create_identity_list(client):
    # Return a list of all the identities.
    # The format is: {"Name": "username", "Type": "User", "InlinePolicies": ["Policy1, Policy2], "AttachedPolicies": [policy3_arn]}
    identity_list = []
    users_list = client.list_users()
    role_list = client.list_roles()

    for user in users_list["Users"]:
        user_attached_policies = client.list_attached_user_policies(UserName=user["UserName"])
        attached_policies_list = user_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyArn"])

        user_inline_policies = client.list_user_policies(UserName=user["UserName"])

        identity_list.append(
            {"Name": user["UserName"], "Type": "User", "InlinePolicies": user_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list})

    for role in role_list["Roles"]:
        role_attached_policies = client.list_attached_role_policies(RoleName=role["RoleName"])
        attached_policies_list = role_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyArn"])

        role_inline_policies = client.list_role_policies(RoleName=role["RoleName"])

        identity_list.append(
            {"Name": role["RoleName"], "Type": "Role", "InlinePolicies": role_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list})

    return identity_list


def get_affected_resources(action_parameter, identity_actions_list):
    # Get the action parameter and the actions list in format [{'action': 'a4b:Get*', 'resource': '*'}], and return a list of the affected resources.
    affected_resources = []
    for policy_action in identity_actions_list:
        if re.search(policy_action["action"], action_parameter):
            affected_resources.append(policy_action["resource"])
            if policy_action["resource"] == "*":
                affected_resources = ["*"]
                break

    return affected_resources


def get_managed_policy_content(client, policy_arn):
    # Get a policy_arn and return a list of its statements.
    # This work for now only for managed policy because we get ARN (inline doesn't have ARN). Need to make more generic.
    policy_details = client.get_policy(PolicyArn=policy_arn)
    default_version_id = policy_details["Policy"]["DefaultVersionId"]
    policy_content = client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
    policy_statement = policy_content["PolicyVersion"]["Document"]["Statement"]
    return policy_statement


def get_inline_policy_content(client, identity_name, type, policy_name):
    if type == "User":
        policy_content = client.get_user_policy(PolicyName=policy_name, UserName=identity_name)
    elif type == "Role":
        policy_content = client.get_role_policy(PolicyName=policy_name, RoleName=identity_name)
    else:
        print("Error getting inline policy, quiting")
        exit()
    policy_statement = policy_content["PolicyDocument"]["Statement"]
    return policy_statement


def statement_parser(statement, identity_allow_list, identity_deny_list):
    # Function gets a policy statement and parse it to split the content between the allow and deny list.
    statement_actions = [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
    if statement["Effect"] == "Allow":
        for action in statement_actions:
            identity_allow_list.append({"action": action, "resource": statement["Resource"]})
    if statement["Effect"] == "Deny":
        for action in statement_actions:
            identity_deny_list.append({"action": action, "resource": statement["Resource"]})
    return identity_allow_list, identity_deny_list


def create_allow_deny_lists(client, identity):
    # Function gets an identity from identity list and return two lists:
    # Allow list -> The list contains all allow actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]
    # Deny list -> The list contains all deny actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]
    identity_allow_list, identity_deny_list = [], []
    for attached_policy in identity["AttachedPolicies"]:
        policy_statements = get_managed_policy_content(client, attached_policy)
        for statement in policy_statements:
            statement_parser(statement, identity_allow_list, identity_deny_list)

    for inline_policy_name in identity["InlinePolicies"]:
        policy_statements = get_inline_policy_content(client, identity["Name"], identity["Type"], inline_policy_name)
        for statement in policy_statements:
            statement_parser(statement, identity_allow_list, identity_deny_list)

    return identity_allow_list, identity_deny_list


def who_can(session, action_parameter):
    client = session.client("iam")
    identity_list = create_identity_list(client)

    with open(f"{action_parameter.replace(':', '_')}.csv", "w", newline="") as output_file:
        writer = csv.writer(output_file)
        output_file.write("Identity Name,Identity Type,Allow on,Deny on\n")
        for identity in identity_list:
            identity_allow_list, identity_deny_list = create_allow_deny_lists(client, identity)

            allow_affected_resources = get_affected_resources(action_parameter, identity_allow_list)
            deny_affected_resources = get_affected_resources(action_parameter, identity_deny_list)

            if deny_affected_resources == ["*"]:
                continue
            if not allow_affected_resources: # There's no allow on this action at all. Move to next identity.
                continue
            if allow_affected_resources == deny_affected_resources: # Regarding the discussed action, resources are the same for Allow and Deny effects. Move to next identity.
                continue
            else:
                writer.writerow([f"{identity['Name']}", f"{identity['Type']}", f"{', '.join(allow_affected_resources)}", f"{', '.join(deny_affected_resources)}"])
