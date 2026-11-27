from iamosaic.cli import main


def test_missing_policy_file_is_usage_error(capsys):
    assert main(["definitely-missing-policy.json"]) == 2
    assert "cannot read" in capsys.readouterr().err.lower()
