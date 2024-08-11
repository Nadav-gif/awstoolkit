def get_identity_by_action(action, session):
    client = session.client("iam")
    users_list = client.list_users()
    role_list = client.list_roles()
    identity_list = []

    for user in users_list["Users"]:

        user_attached_policies = client.list_attached_user_policies(UserName=user["UserName"])
        attached_policies_list = user_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyName"])

        user_inline_policies = client.list_user_policies(UserName=user["UserName"])

        identity_list.append(
            {"Name": user["UserName"], "Type": "User", "InlinePolicies": user_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list})

    for role in role_list["Roles"]:
        role_attached_policies = client.list_attached_role_policies(RoleName=role["RoleName"])
        attached_policies_list = role_attached_policies["AttachedPolicies"]
        policies_list = []
        for attached_policy in attached_policies_list:
            policies_list.append(attached_policy["PolicyName"])

        role_inline_policies = client.list_role_policies(RoleName=role["RoleName"])

        identity_list.append(
            {"Name": role["RoleName"], "Type": "Role", "InlinePolicies": role_inline_policies["PolicyNames"],
             "AttachedPolicies": policies_list})

    for identity in identity_list:
        print(identity)
        pass
