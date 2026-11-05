def _statements(policy):
    if not isinstance(policy,dict): return []
    statements=policy.get("Statement")
    if statements is None: return []
    if isinstance(statements,dict): statements=[statements]
    if not isinstance(statements,list): return []
    return [s for s in statements if isinstance(s,dict)]

def _as_list(value):
    if value is None: return []
    if isinstance(value,str): return [value]
    if isinstance(value,list): return [v for v in value if isinstance(v,str)]
    return []

def _is_broad_action(action):
    return action.strip()=="*"

def _is_wildcard_action(action):
    return "*" in action

def _is_broad_resource(resource):
    return resource.strip()=="*"

def analyze_policy(policy: dict):
    findings=[]
    for index,statement in enumerate(_statements(policy)):
        actions=_as_list(statement.get("Action"))
        resources=_as_list(statement.get("Resource"))
        # A Deny statement removes permissions, so it is never an over-permission grant.
        if str(statement.get("Effect") or "Allow").strip().lower()=="deny": continue
        broad_action=any(_is_broad_action(a) for a in actions)
        wildcard_action=any(_is_wildcard_action(a) for a in actions)
        broad_resource=any(_is_broad_resource(r) for r in resources)
        if not (wildcard_action or broad_resource): continue
        findings.append({
            "rule_id":"CG001","severity":"high" if broad_action and broad_resource else "medium",
            "statement_index":index,"actions":actions,"resources":resources,
            "recommendation":"Replace wildcard permissions with the smallest required action and resource set."
        })
    return findings

def policy_edges(policy: dict):
    return [{"principal":statement.get("Principal") or "unspecified","action":_as_list(statement.get("Action")),
             "resource":_as_list(statement.get("Resource")),"effect":statement.get("Effect") or "unspecified"}
            for statement in _statements(policy)]
