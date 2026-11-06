"""Configure the OAuth and organization boundaries through authenticated HTTP."""

from __future__ import annotations

from delivery_journey import require

ACCEPT = "organization.invitation.accept"
READ = "organization.context.read"
MEMBERS = "organization.members.read"
MANAGE = "organization.members.manage"
ADMIN = [READ, MEMBERS, MANAGE]
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


def allow_scopes(api):
    environment, _ = api.call("GET", api.base)
    current = environment["activeConfigurationVersionId"]
    version, _ = api.call("GET", api.base + "/configurationVersions/" + current)
    document = version["configurationDocument"]
    document["scopeAllowlist"] = ["openid", "read", "offline_access", ACCEPT, "documents"]
    created, _ = api.call(
        "POST",
        api.base + "/configurationVersions",
        {
            "baseConfigurationVersionId": current,
            "configurationDocument": document,
            "comment": "explicit finite invitation and resource scope vocabulary",
        },
        expected=201,
    )
    api.call(
        "POST",
        api.base + "/configurationVersions/" + created["id"] + "/activate",
        {"allowSecurityDowngrade": True, "reason": "explicit invitation and resource scopes"},
    )


def configure(api, issuer):
    client = api.client
    environment, _ = api.call("GET", api.base)
    updated, _ = api.call(
        "PATCH",
        api.base + "/clients/" + client["id"],
        {
            "baseConfigurationVersionId": environment["activeConfigurationVersionId"],
            "allowedGrantTypes": ["authorization_code", "refresh_token", EXCHANGE],
            "allowedScopes": ["read", "offline_access", ACCEPT, "documents"],
            "comment": "finite invitation and organization access profile",
        },
    )
    secret, _ = api.call(
        "POST",
        api.base + "/clients/" + client["id"] + "/clientSecrets",
        {
            "baseConfigurationVersionId": updated["environment"]["activeConfigurationVersionId"],
            "expiresInDays": 1,
            "comment": "owned acceptance client",
        },
        expected=201,
    )
    invitations, organizations = issuer + "/organization-invitations", issuer + "/organizations"
    for label, audience in [("invitations", invitations), ("resource", organizations)]:
        _, tag = api.call("GET", api.path)
        api.call(
            "POST",
            api.path + "/targets",
            {"audience": audience, "management": True, "reason": "explicit " + label},
            tag=tag,
            key="target-" + label,
        )
    binding, tag = api.binding
    api.call(
        "PATCH",
        api.path + "/clients/" + binding["id"],
        {
            "active": True,
            "targets": [
                {"audience": "management-api", "privileges": ["organization.members.manage"]},
                {"audience": invitations, "privileges": [ACCEPT]},
                {"audience": organizations, "privileges": ADMIN},
            ],
            "reason": "least privilege registered targets",
        },
        tag=tag,
        key="protocol-binding",
    )
    _, tag = api.call("GET", api.path + "/role-policy")
    api.call(
        "PUT",
        api.path + "/role-policy",
        {
            "roles": [
                {
                    "key": "admin",
                    "privileges": ADMIN,
                    "managesMembers": True,
                    "assignableRoles": ["admin", "member"],
                },
                {
                    "key": "member",
                    "privileges": [READ],
                    "managesMembers": False,
                    "assignableRoles": [],
                },
                {
                    "key": "auditor",
                    "privileges": [READ],
                    "managesMembers": False,
                    "assignableRoles": [],
                },
            ],
            "reason": "explicit own resource read permission",
        },
        tag=tag,
        key="protocol-roles",
    )
    _, tag = api.call("GET", api.path)
    api.call(
        "POST",
        api.path + "/targets/introspection-recipients/replace",
        {
            "audience": organizations,
            "clientRegistrationIds": [client["id"]],
            "reason": "explicit introspection disclosure to the registered client",
        },
        tag=tag,
        key="protocol-introspection",
    )
    policy = {"version": 1, "targets": [], "rules": []}
    for audience, scope in [(invitations, ACCEPT), (organizations, "documents")]:
        policy["targets"].append({"audience": audience, "resourceAliases": []})
        policy["rules"].append(
            {
                "clientId": client["clientIdentifier"],
                "sourceAudience": issuer + "/userinfo",
                "targetAudience": audience,
                "scopes": [{"targetScope": scope, "sourceScopes": ["read"]}],
                "defaultScopes": [scope],
            }
        )
    patched, _ = api.call(
        "PATCH",
        api.base + "/policies",
        {
            "baseConfigurationVersionId": secret["environment"]["activeConfigurationVersionId"],
            "tokenExchange": policy,
            "allowSecurityDowngrade": True,
            "reason": "explicit finite code-to-invitation and selected organization exchange",
        },
    )
    require(
        not patched["runtimeActivation"]["runtimeReloaded"], "restart required by snapshot contract"
    )
    return {"client": client["clientIdentifier"], "secret": secret["clientSecretValue"]}
