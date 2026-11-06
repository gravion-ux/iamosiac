import json

from iamosaic import cli


def _write_policy(tmp_path, payload, name="policy.json", encoding="utf-8"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding=encoding)
    return path


def test_cli_reports_a_missing_file_without_a_traceback(tmp_path, capsys):
    code = cli.main([str(tmp_path / "absent.json")])
    captured = capsys.readouterr()
    assert code == cli.EXIT_USAGE
    assert "iamosaic:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reports_invalid_json_without_a_traceback(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_POLICY
    assert "invalid JSON" in captured.err
    assert "Traceback" not in captured.err


def test_cli_rejects_a_non_object_policy_root(tmp_path, capsys):
    path = tmp_path / "list.json"
    path.write_text(json.dumps(["not-a-policy"]), encoding="utf-8")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_POLICY
    assert "must contain a JSON object" in captured.err
    assert "Traceback" not in captured.err


def test_cli_reads_a_policy_that_starts_with_a_byte_order_mark(tmp_path, capsys):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps({"Statement": {"Action": "*", "Resource": "*"}}),
                    encoding="utf-8-sig")
    code = cli.main([str(path)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_OK
    report = json.loads(captured.out)
    assert report["findings"]


def test_cli_prints_a_json_report(tmp_path, capsys):
    path = _write_policy(tmp_path, {"Statement": {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}})
    cli.main([str(path)])
    report = json.loads(capsys.readouterr().out)
    assert report["tool"] == "IAMosaic"
    assert report["mode"] == "offline-policy-analysis"
    assert report["schema_version"] == 1
    assert report["policy_version"] is None
    assert report["findings"][0]["rule_id"] == "CG001"
    assert "notice" in report


def test_cli_writes_the_report_to_the_output_path(tmp_path, capsys):
    path = _write_policy(tmp_path, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    output = tmp_path / "report.json"
    code = cli.main([str(path), "--output", str(output)])
    capsys.readouterr()
    assert code == cli.EXIT_OK
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["findings"][0]["rule_id"] == "CG001"


def test_cli_reports_an_unwritable_output_path_without_a_traceback(tmp_path, capsys):
    path = _write_policy(tmp_path, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    output = tmp_path / "missing-directory" / "report.json"
    code = cli.main([str(path), "--output", str(output)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_INVALID_POLICY
    assert "iamosaic:" in captured.err
    assert "Traceback" not in captured.err


def test_cli_fail_on_findings_returns_a_failing_status(tmp_path, capsys):
    path = _write_policy(tmp_path, {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    code = cli.main([str(path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_INVALID_POLICY


def test_cli_fail_on_findings_succeeds_on_a_clean_policy(tmp_path, capsys):
    path = _write_policy(
        tmp_path,
        {
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:role/build"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::b/*",
            }
        },
    )
    code = cli.main([str(path), "--fail-on-findings"])
    capsys.readouterr()
    assert code == cli.EXIT_OK
