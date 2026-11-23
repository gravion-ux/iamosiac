"""Parser edge cases: empty, malformed, duplicated and boundary-value input.

The analyzer is deliberately forgiving — exported policies in the wild carry
malformed entries, odd types and padded strings. These tests pin down exactly
how far that forgiveness goes, so a future refactor cannot silently change
what is (and is not) reported.
"""
from iamosaic.analyzer import analyze_policy, policy_edges, policy_version

# --- empty and missing input -------------------------------------------------


def test_empty_policy_has_no_findings_or_edges():
    assert analyze_policy({}) == []
    assert policy_edges({}) == []


def test_empty_statement_list_has_no_findings_or_edges():
    assert analyze_policy({"Statement": []}) == []
    assert policy_edges({"Statement": []}) == []


def test_statement_with_a_scalar_type_is_ignored():
    assert analyze_policy({"Statement": "Allow everything"}) == []
    assert analyze_policy({"Statement": 42}) == []
    assert policy_edges({"Statement": "Allow everything"}) == []


def test_empty_statement_object_produces_an_edge_but_no_finding():
    policy = {"Statement": [{}]}
    assert analyze_policy(policy) == []
    edges = policy_edges(policy)
    assert len(edges) == 1
    assert edges[0]["principal"] == "unspecified"
    assert edges[0]["effect"] == "unspecified"
    assert edges[0]["action"] == []


# --- duplicates are reported, not merged -------------------------------------


def test_duplicate_statements_are_each_reported():
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    findings = analyze_policy({"Statement": [statement, dict(statement)]})
    assert [finding["statement_index"] for finding in findings] == [0, 1]


def test_duplicate_actions_in_one_statement_produce_one_finding():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Action": ["*", "*"], "Resource": "*"}}
    )
    assert len(findings) == 1
    assert findings[0]["actions"] == ["*", "*"]


# --- malformed field values ---------------------------------------------------


def test_non_string_action_entries_are_filtered_out():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Action": [123, None, "*"], "Resource": "*"}}
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CG001"
    assert findings[0]["actions"] == ["*"]
    assert findings[0]["severity"] == "high"


def test_a_numeric_action_value_is_ignored():
    policy = {"Statement": {"Effect": "Allow", "Action": 42, "Resource": "arn:aws:s3:::b/*"}}
    assert analyze_policy(policy) == []
    assert policy_edges(policy)[0]["action"] == []


def test_a_nested_list_statement_entry_is_skipped_but_keeps_its_index():
    findings = analyze_policy(
        {"Statement": [[{"Action": "*"}], {"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    )
    assert findings and findings[0]["statement_index"] == 1


# --- boundary values ----------------------------------------------------------


def test_a_whitespace_padded_wildcard_action_is_still_broad():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Action": " * ", "Resource": "*"}}
    )
    assert findings and findings[0]["severity"] == "high"


def test_a_broad_resource_alone_does_not_raise_severity_to_high():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}}
    )
    assert findings and findings[0]["rule_id"] == "CG001"
    assert findings[0]["severity"] == "medium"


def test_a_public_principal_with_scoped_grants_is_medium():
    findings = analyze_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        }
    )
    finding = next(item for item in findings if item["rule_id"] == "CG002")
    assert finding["severity"] == "medium"


def test_an_empty_exclusion_list_is_not_a_grant_by_exclusion():
    findings = analyze_policy(
        {"Statement": {"Effect": "Allow", "NotAction": [], "Action": "s3:GetObject",
                       "Resource": "x"}}
    )
    assert findings == []


# --- Effect handling ------------------------------------------------------------


def test_effect_matching_is_case_and_whitespace_insensitive_for_deny():
    for effect in ("DENY", " Deny ", "deny"):
        findings = analyze_policy(
            {"Statement": {"Effect": effect, "Action": "*", "Resource": "*"}}
        )
        assert findings == [], effect


def test_a_missing_effect_is_treated_as_a_grant():
    findings = analyze_policy({"Statement": {"Action": "*", "Resource": "*"}})
    assert findings and findings[0]["rule_id"] == "CG001"


def test_an_unrecognised_effect_is_treated_as_a_grant():
    # Only an explicit Deny removes permissions; anything else is analysed as
    # a grant so an unusual Effect value cannot hide a broad statement.
    findings = analyze_policy(
        {"Statement": {"Effect": "Permit", "Action": "*", "Resource": "*"}}
    )
    assert findings and findings[0]["rule_id"] == "CG001"


def test_deny_statements_still_appear_in_the_edge_list():
    edges = policy_edges({"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}})
    assert len(edges) == 1
    assert edges[0]["effect"] == "Deny"


# --- Principal shapes -----------------------------------------------------------


def test_a_wildcard_in_a_principal_list_is_flagged():
    findings = analyze_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": ["arn:aws:iam::123456789012:root", "*"],
                "Action": "s3:GetObject",
                "Resource": "x",
            }
        }
    )
    finding = next(item for item in findings if item["rule_id"] == "CG002")
    assert finding["principals"] == ["arn:aws:iam::123456789012:root", "*"]


def test_a_wildcard_under_an_unrecognised_principal_key_is_flagged():
    findings = analyze_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Custom": "*"},
                "Action": "s3:GetObject",
                "Resource": "x",
            }
        }
    )
    assert any(finding["rule_id"] == "CG002" for finding in findings)


def test_an_empty_principal_is_not_public():
    for principal in ("", {"AWS": ""}, {"AWS": []}):
        findings = analyze_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Principal": principal,
                    "Action": "s3:GetObject",
                    "Resource": "x",
                }
            }
        )
        assert findings == [], principal


# --- policy version -------------------------------------------------------------


def test_a_non_string_version_is_ignored():
    assert policy_version({"Version": 20121017}) is None


def test_a_padded_version_string_is_trimmed():
    assert policy_version({"Version": " 2012-10-17 "}) == "2012-10-17"
