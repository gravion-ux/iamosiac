import iamosaic
from iamosaic import analyzer
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


# --- CG001 statement_index points at the original policy position ------------


def test_statement_index_refers_to_the_original_policy_position():
    findings = analyze_policy(
        {"Statement": [None, {"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    )
    assert findings and findings[0]["statement_index"] == 1


def test_statement_index_is_stable_when_a_leading_statement_is_malformed():
    findings = analyze_policy(
        {"Statement": ["not-a-statement", {"Effect": "Allow", "Action": "s3:*", "Resource": "x"}]}
    )
    assert findings and findings[0]["statement_index"] == 1


def test_edges_report_the_original_statement_index():
    edges = policy_edges({"Statement": [None, {"Action": "s3:GetObject"}]})
    assert edges and edges[0]["statement_index"] == 1


# --- CG002 wildcard principals ----------------------------------------------


def test_wildcard_principal_is_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}}
    )
    rules = [finding["rule_id"] for finding in findings]
    assert "CG002" in rules


def test_wildcard_principal_in_map_form_is_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "x"}}
    )
    assert any(finding["rule_id"] == "CG002" for finding in findings)


def test_wildcard_service_principal_is_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Principal": {"Service": "*"}, "Action": "s3:GetObject", "Resource": "x"}}
    )
    assert any(finding["rule_id"] == "CG002" for finding in findings)


def test_specific_principal_is_not_flagged():
    findings = analyze_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/build"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        }
    )
    assert findings == []


def test_deny_statement_with_wildcard_principal_is_not_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Deny", "Principal": "*", "Action": "*", "Resource": "*"}}
    )
    assert findings == []


def test_public_principal_finding_reports_the_principal():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "x"}}
    )
    finding = next(item for item in findings if item["rule_id"] == "CG002")
    assert finding["principals"] == ["*"]


# --- CG003 grants by exclusion ----------------------------------------------


def test_not_action_grant_is_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}}
    )
    assert any(finding["rule_id"] == "CG003" for finding in findings)


def test_not_resource_grant_is_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::secret/*"}}
    )
    assert any(finding["rule_id"] == "CG003" for finding in findings)


def test_not_action_finding_keeps_the_excluded_actions():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "NotAction": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}}
    )
    finding = next(item for item in findings if item["rule_id"] == "CG003")
    assert finding["not_action"] == ["s3:GetObject", "s3:PutObject"]
    assert finding["severity"] == "high"


def test_deny_statement_with_not_action_is_not_flagged():
    findings = analyze_policy(
        {"Statement": {"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}}
    )
    assert findings == []


# --- principal normalisation -------------------------------------------------


def test_edges_expose_normalised_principals():
    edges = policy_edges(
        {"Statement": {"Principal": {"AWS": ["arn:aws:iam::1:user/a", "*"]}, "Action": "s3:GetObject"}}
    )
    assert edges[0]["principals"] == ["arn:aws:iam::1:user/a", "*"]


def test_edges_keep_the_raw_principal_for_backwards_compatibility():
    edges = policy_edges({"Statement": {"Principal": {"AWS": "*"}, "Action": "s3:GetObject"}})
    assert edges[0]["principal"] == {"AWS": "*"}


def test_edges_report_missing_principal_as_unspecified():
    edges = policy_edges({"Statement": {"Action": "s3:GetObject"}})
    assert edges[0]["principal"] == "unspecified"
    assert edges[0]["principals"] == []


def test_edges_expose_exclusion_lists():
    edges = policy_edges(
        {"Statement": {"Effect": "Allow", "NotAction": "s3:GetObject", "NotResource": "arn:aws:s3:::x/*"}}
    )
    assert edges[0]["not_action"] == ["s3:GetObject"]
    assert edges[0]["not_resource"] == ["arn:aws:s3:::x/*"]


# --- policy version ----------------------------------------------------------


def test_policy_version_is_reported():
    assert analyzer.policy_version({"Version": "2012-10-17"}) == "2012-10-17"


def test_policy_version_is_none_when_absent_or_blank():
    assert analyzer.policy_version({}) is None
    assert analyzer.policy_version({"Version": "  "}) is None
    assert analyzer.policy_version([]) is None


# --- public API --------------------------------------------------------------


def test_package_exposes_the_public_api():
    assert iamosaic.analyze_policy is analyze_policy
    assert iamosaic.policy_edges is policy_edges
    assert iamosaic.policy_version is analyzer.policy_version
    assert iamosaic.__version__


def test_finding_schema_is_consistent_across_rules():
    findings = analyze_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "*",
                "Resource": "*",
                "NotAction": "s3:GetObject",
                "Sid": "Broad",
            }
        }
    )
    assert len(findings) == 3
    for finding in findings:
        assert set(finding) >= {
            "rule_id",
            "severity",
            "statement_index",
            "sid",
            "actions",
            "resources",
            "principals",
            "recommendation",
        }
        assert finding["sid"] == "Broad"
        assert finding["statement_index"] == 0
