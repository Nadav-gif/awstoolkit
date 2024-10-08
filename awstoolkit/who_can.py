import re
import csv
import os
from awstoolkit.utils import get_policies_intersection, get_managed_policy_content, get_inline_policy_content, statement_parser, \
    get_affected_resources
from awstoolkit.authenticator import authenticate
from awstoolkit.parameter_builder import action_parameter_validator


def create_identity_list(client):
    # Return a list of all the identities.
    # The format is: {"Name": "username", "Type": "User", "InlinePolicies": ["Policy1, Policy2], "AttachedPolicies": [policy3_arn], "Arn":"arn:aws:iam..."}
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
             "PermissionsBoundary": user_permissions_boundary, "Arn": user["Arn"]})

    for role in role_list["Roles"]:
        role_attached_policies = client.list_attached_role_policies(RoleName=role["RoleName"])
        attached_policies_list = role_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyArn"])

        role_inline_policies = client.list_role_policies(RoleName=role["RoleName"])

        # Get the permissions boundary of the role
        role_permissions_boundary = client.get_role(RoleName=role["RoleName"])
        if "PermissionsBoundary" in role_permissions_boundary["Role"].keys():
            role_permissions_boundary = role_permissions_boundary["Role"]["PermissionsBoundary"]["PermissionsBoundaryArn"]
        else:
            role_permissions_boundary = ""

        identity_list.append(
            {"Name": role["RoleName"], "Type": "Role", "InlinePolicies": role_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list, "PermissionsBoundary": role_permissions_boundary, "Arn":role["Arn"]})

    return identity_list


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
    allow_list, deny_list = get_scp_content(sessions, target_id, allow_list, deny_list)  # The first comparison is between the identity policies and the SCPs that affect it directly
    organizations_client = sessions[1].client("organizations")

    while True:
        daddy = organizations_client.list_parents(ChildId=target_id)  # who's your daddy
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


def create_allow_deny_lists(client, identity):
    # Function gets an identity from identity list and return two lists:
    # Allow list -> The list contains all allow actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]
    # Deny list -> The list contains all deny actions in all policies that affect the identity, i.e [{'action': 'a4b:Get*', 'resource': '*'}]
    identity_allow_list, identity_deny_list = [], []
    for attached_policy in identity["AttachedPolicies"]:
        policy_statements = get_managed_policy_content(client, attached_policy)
        for statement in policy_statements:
            identity_allow_list, identity_deny_list = statement_parser(statement, identity_allow_list, identity_deny_list)

    for inline_policy_name in identity["InlinePolicies"]:
        policy_statements = get_inline_policy_content(client, identity["Name"], identity["Type"], inline_policy_name)
        for statement in policy_statements:
            identity_allow_list, identity_deny_list = statement_parser(statement, identity_allow_list, identity_deny_list)

    if identity["Type"] == "User":  # checks permissions for the group (only users can be in a group)
        for group_inline_policy in identity["PoliciesFromGroups"]:
            policy_statement = get_inline_policy_content(client, group_inline_policy["GroupName"], "Group", group_inline_policy["PolicyName"])
            for statement in policy_statement:
                identity_allow_list, identity_deny_list = statement_parser(statement, identity_allow_list, identity_deny_list)

    return identity_allow_list, identity_deny_list


def who_can_execute(sessions, action_parameter, include_scp, output_path, output_format):
    iam_client = sessions[0].client("iam")
    identity_list = create_identity_list(iam_client)
    final_output_list = []

    for identity in identity_list:
        identity_allow_list, identity_deny_list = create_allow_deny_lists(iam_client, identity)
        if identity["PermissionsBoundary"]:
            identity_allow_list, identity_deny_list = calculate_permission_boundary(iam_client, identity_allow_list,
                                                                                    identity_deny_list,
                                                                                    identity["PermissionsBoundary"])
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

        output_object = {"Name": identity["Name"], "Type": identity["Type"], "Allowed": allow_affected_resources,
                         "Denied": deny_affected_resources, "Arn": identity["Arn"]}
        final_output_list.append(output_object)

    if output_format.lower() == "csv":
        output_filepath = f"{output_path}/{action_parameter.replace(':', '_')}.csv"
        os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
        with open(output_filepath, "w", newline="") as output_file:
            writer = csv.writer(output_file)
            output_file.write("Identity Name,Identity Type,Allow on,Deny on\n")

            for identity in final_output_list:
                pattern = r"[\[\]]"
                writer.writerow([f"{identity['Name']}", f"{identity['Type']}", f"{re.sub(pattern,'', str(identity['Allowed']))}", f"{re.sub(pattern,'', str(identity['Denied']))}"])

    if output_format.lower() == "json":
        return {"output": final_output_list}


# who_can run when called from the code.
def who_can(**kwargs):
    sessions = authenticate(profile=kwargs.get("profile"),
                            access_key=kwargs.get("access_key"),
                            secret_key=kwargs.get("secret_key"),
                            session_token=kwargs.get("session_token"),
                            role_arn=kwargs.get("role_arn"))
    action_parameter_validator(sessions[0], kwargs.get("action"))  # returns if the action exists or not
    return who_can_execute(sessions, kwargs.get("action"), include_scp=kwargs.get("include_scp"), output_path="", output_format="json")
