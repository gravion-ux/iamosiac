from iamosaic.analyzer import analyze_policy, policy_edges


def test_wildcard_policy_flagged():
    assert analyze_policy({"Statement":{"Action":"*","Resource":"*"}})[0]["severity"]=="high"


def test_deny_statement_is_not_flagged_as_over_permission():
    findings=analyze_policy({"Statement":{"Effect":"Deny","Action":"*","Resource":"*"}})
    assert findings==[]


def test_service_scoped_wildcard_action_is_flagged():
    findings=analyze_policy({"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::bucket/*"}})
    assert findings and findings[0]["rule_id"]=="CG001"


def test_scoped_resource_wildcard_is_not_flagged():
    findings=analyze_policy({"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}})
    assert findings==[]


def test_allow_wildcard_action_with_scoped_resource_is_flagged():
    findings=analyze_policy({"Statement":{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket/*"}})
    assert findings and findings[0]["severity"]=="medium"


def test_edges_normalise_action_and_resource_to_lists():
    edges=policy_edges({"Statement":{"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}})
    assert edges[0]["action"]==["s3:GetObject"]
    assert edges[0]["resource"]==["arn:aws:s3:::bucket/*"]


def test_null_statement_is_ignored():
    assert analyze_policy({"Statement":None})==[]


def test_malformed_statement_entries_are_ignored():
    assert analyze_policy({"Statement":[None,"not-a-statement"]})==[]


def test_non_dict_policy_is_ignored():
    assert analyze_policy([])==[]
    assert policy_edges([])==[]
