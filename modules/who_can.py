import re
import csv


def create_identity_list(client):
    # Return a list of all the identities.
    # The format is: {"Name": "username", "Type": "User", "InlinePolicies": ["Policy1, Policy2], "AttachedPolicies": [policy3_arn]}
    identity_list = []
    users_list = client.list_users()
    role_list = client.list_roles()

    for user in users_list["Users"]:
        policies_list = []  # The list of attached policies' ARNs
        inline_policies_from_groups = [] # The list of policies that are attached to the user by group, i.e [{"GroupName": "GroupA", "PolicyName": "PolicyA"}]
        user_groups = client.list_groups_for_user(UserName=user["UserName"])

        # Get managed policies of the groups that the user is part of
        for group in user_groups["Groups"]:
            group_managed_policies = client.list_attached_group_policies(GroupName=group["GroupName"])
            for attached_policy in group_managed_policies["AttachedPolicies"]:
                policies_list.append(attached_policy["PolicyArn"])
            group_inline_policies = client.list_group_policies(GroupName=group["GroupName"])
            for policy in group_inline_policies["PolicyNames"]:
                inline_policies_from_groups.append({"GroupName": group["GroupName"], "PolicyName": policy})

        # Get managed policies that are attached directly to the user
        user_attached_policies = client.list_attached_user_policies(UserName=user["UserName"])
        for attached_policy in user_attached_policies["AttachedPolicies"]:
            policies_list.append(attached_policy["PolicyArn"])

        # Get the inline policies of the user
        user_inline_policies = client.list_user_policies(UserName=user["UserName"])

        # Get the permissions boundary of the user
        user_permissions_boundary = client.get_user(UserName=user["UserName"])
        if "PermissionsBoundary" in user_permissions_boundary["User"].keys():
            user_permissions_boundary = user_permissions_boundary["User"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        else:
            user_permissions_boundary = ""

        identity_list.append(
            {"Name": user["UserName"], "Type": "User", "InlinePolicies": user_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list, "PoliciesFromGroups": inline_policies_from_groups,
             "PermissionsBoundary": user_permissions_boundary})

    for role in role_list["Roles"]:
        role_attached_policies = client.list_attached_role_policies(RoleName=role["RoleName"])
        attached_policies_list = role_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyArn"])

        role_inline_policies = client.list_role_policies(RoleName=role["RoleName"])

        identity_list.append(
            {"Name": role["RoleName"], "Type": "Role", "InlinePolicies": role_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list, "PermissionsBoundary": ""})

    return identity_list


def get_policies_intersection(actions_list, restricted_list):
    # Get two lists of the format [{'action': 'a4b:Get*', 'resource': '*'}], and return the intersection between them
    # This is useful to bring an allow_list from identities' policies and a list of the permission limiter (like SCP, or Permission Boundary). and get the actual permissions.
    calculated_allow_list = []
    for action in actions_list:
        for boundary_action in restricted_list:
            final_resource_list = []

            if re.search(boundary_action["action"].replace("*", ".*"), action["action"]):  # The Allow list action is contained in the PB (PB is bigger)
                for resource in action["resource"]:
                    for boundary_resource in boundary_action["resource"]:
                        if re.search(boundary_resource.replace("*", ".*"), resource):
                            final_resource_list.append(resource)
                        elif re.search(resource.replace("*", ".*"), boundary_resource):
                            final_resource_list.append(boundary_resource)
                calculated_allow_list.append({"action": action["action"], "resource": final_resource_list}) #  The final action is the one from allow list

            if re.search(action["action"].replace("*", ".*"), boundary_action["action"]):  # The PB action is contained in the Allow List (AL is bigger)
                for resource in action["resource"]:
                    for boundary_resource in boundary_action["resource"]:
                        if re.search(boundary_resource.replace("*", ".*"), resource):
                            final_resource_list.append(resource)
                        elif re.search(resource.replace("*", ".*"), boundary_resource):
                            final_resource_list.append(boundary_resource)
                calculated_allow_list.append({"action": boundary_action["action"], "resource": final_resource_list}) #  The final action is the one from the PB

    return calculated_allow_list


def get_scp_content(sessions, target_id, allow_list, deny_list):
    organizations_client = sessions[1].client("organizations")
    account_scp_policies = organizations_client.list_policies_for_target(TargetId=target_id,
                                                                         Filter="SERVICE_CONTROL_POLICY")
    scp_allow_list, scp_deny_list = [], []
    for policy in account_scp_policies["Policies"]:
        scp_policy_content = organizations_client.describe_policy(PolicyId=policy["Id"])["Policy"]["Content"]
        scp_policy_content = eval(scp_policy_content)
        for statement in scp_policy_content["Statement"]:
            scp_allow_list, scp_deny_list = statement_parser(statement, scp_allow_list, scp_deny_list)

    calculated_allow_list = get_policies_intersection(allow_list, scp_allow_list)
    calculated_deny_list = deny_list + scp_deny_list

    return calculated_allow_list, calculated_deny_list


def calculate_scp(sessions, allow_list, deny_list):
    session = sessions[0]
    sts_client = session.client("sts")
    target_id = sts_client.get_caller_identity()["Account"]
    allow_list, deny_list = get_scp_content(sessions, target_id, allow_list, deny_list) # The first comparison is between the identity policies and the SCPs that affect it directly
    organizations_client = sessions[1].client("organizations")

    while True:
        daddy = organizations_client.list_parents(ChildId=target_id)
        daddy_id = daddy["Parents"][0]["Id"]
        daddy_type = daddy["Parents"][0]["Type"]
        target_id = daddy_id
        allow_list, deny_list = get_scp_content(sessions, target_id, allow_list, deny_list)
        if daddy_type == "ROOT":  # Daddy's home
            break

    return allow_list, deny_list


def calculate_permission_boundary(client, allow_list, deny_list, permissions_boundary):
    # The function gets identity allow list format [{'action': 'a4b:Get*', 'resource': '*'}] and the permission boundary in the same format.
    # It then makes the calculation and return a list in the same format, but limit it only for the relevant actions and resources that exist in both.
    permissions_boundary_content = get_managed_policy_content(client, permissions_boundary)
    permissions_boundary_allow_list, permission_boundary_deny_list = [], []
    for statement in permissions_boundary_content:
        permissions_boundary_allow_list, permission_boundary_deny_list = statement_parser(statement, permissions_boundary_allow_list, permission_boundary_deny_list)

    calculated_allow_list = get_policies_intersection(allow_list, permissions_boundary_allow_list)
    calculated_deny_list = deny_list + permission_boundary_deny_list

    return calculated_allow_list, calculated_deny_list


def get_affected_resources(action_parameter, identity_actions_list):
    # Get the action parameter and the actions list in format [{'action': 'a4b:Get*', 'resource': '*'}], and return a list of the affected resources.
    affected_resources = []
    for policy_action in identity_actions_list:
        if re.search(policy_action["action"].lower().replace("*", ".*"), action_parameter.lower()):
            affected_resources.append(policy_action["resource"])
            if policy_action["resource"] == "*" or policy_action["resource"] == ["*"]:
                affected_resources = ["*"]
                break
    flattened_resources = [item for sublist in affected_resources for item in
                          (sublist if isinstance(sublist, list) else [sublist])]
    return list(set(flattened_resources))


def get_managed_policy_content(client, policy_arn):
    # Get a policy_arn and return a list of its statements.
    # This work for now only for managed policy because we get ARN (inline doesn't have ARN). Need to make more generic.
    policy_details = client.get_policy(PolicyArn=policy_arn)
    default_version_id = policy_details["Policy"]["DefaultVersionId"]
    policy_content = client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
    policy_statement = policy_content["PolicyVersion"]["Document"]["Statement"]
    return policy_statement


def get_inline_policy_content(client, identity_name, identity_type, policy_name):
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
    statement_actions = [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
    statement_resources = [statement["Resource"]] if isinstance(statement["Resource"], str) else statement["Resource"]
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

    if identity["Type"] == "User":
        for group_inline_policy in identity["PoliciesFromGroups"]:
            policy_statement = get_inline_policy_content(client, group_inline_policy["GroupName"], "Group", group_inline_policy["PolicyName"])
            for statement in policy_statement:
                statement_parser(statement, identity_allow_list, identity_deny_list)

    return identity_allow_list, identity_deny_list


def who_can(sessions, action_parameter, include_scp):
    iam_client = sessions[0].client("iam")
    identity_list = create_identity_list(iam_client)

    with open(f"{action_parameter.replace(':', '_')}.csv", "w", newline="") as output_file:
        writer = csv.writer(output_file)
        output_file.write("Identity Name,Identity Type,Allow on,Deny on\n")
        for identity in identity_list:
            identity_allow_list, identity_deny_list = create_allow_deny_lists(iam_client, identity)
            if identity["PermissionsBoundary"]:
                identity_allow_list, identity_deny_list = calculate_permission_boundary(iam_client, identity_allow_list, identity_deny_list, identity["PermissionsBoundary"])
            if include_scp:
                identity_allow_list, identity_deny_list = calculate_scp(sessions, identity_allow_list, identity_deny_list)
            allow_affected_resources = get_affected_resources(action_parameter, identity_allow_list)
            deny_affected_resources = get_affected_resources(action_parameter, identity_deny_list)
            if deny_affected_resources == ["*"]:  # Deny all - Move to next identity
                continue
            if not allow_affected_resources:  # There's no allow on this action at all. Move to next identity.
                continue
            if allow_affected_resources == deny_affected_resources:  # Regarding the discussed action, resources are the same for Allow and Deny effects. Move to next identity.
                continue
            else:
                pattern = r"[\[\]]"
                writer.writerow([f"{identity['Name']}", f"{identity['Type']}", f"{re.sub(pattern,'', str(allow_affected_resources))}", f"{re.sub(pattern,'', str(deny_affected_resources))}"])
