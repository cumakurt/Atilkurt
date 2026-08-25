"""Command-line argument validation and logging tests."""

import logging
import os

import pytest

from AtilKurt import _PrivateFileHandler, build_parser, validate_cli_arguments


REQUIRED_ARGUMENTS = ["--domain", "example.com", "--username", "auditor"]


def parse_arguments(*extra_arguments):
    parser = build_parser()
    arguments = parser.parse_args([*REQUIRED_ARGUMENTS, *extra_arguments])
    validate_cli_arguments(parser, arguments)
    return arguments


def test_version_flag_does_not_require_domain_arguments():
    parser = build_parser()
    with pytest.raises(SystemExit) as caught:
        parser.parse_args(["--version"])
    assert caught.value.code == 0


@pytest.mark.parametrize(
    "arguments",
    [
        ("--rate-limit", "-0.1"),
        ("--hourly-rate", "0"),
        ("--timeout", "0"),
        ("--timeout", "301"),
        ("--page-size", "5001"),
        ("--max-workers", "65"),
        ("--random-delay", "5", "1"),
    ],
)
def test_invalid_numeric_arguments_are_rejected(arguments):
    with pytest.raises(SystemExit):
        parse_arguments(*arguments)


def test_non_inline_report_mode_can_be_selected():
    arguments = parse_arguments("--no-single-file-report")

    assert arguments.single_file_report is False


def test_valid_delay_range_is_accepted():
    arguments = parse_arguments("--random-delay", "0.25", "1.5")

    assert arguments.random_delay == [0.25, 1.5]


def test_domain_name_is_the_default_ldap_server():
    arguments = parse_arguments()

    assert arguments.dc_ip == "example.com"


def test_report_language_defaults_to_english():
    arguments = parse_arguments()

    assert arguments.language == "en"


def test_turkish_report_language_can_be_selected():
    arguments = parse_arguments("--lan", "tr")

    assert arguments.language == "tr"


def test_explicit_domain_controller_overrides_default():
    arguments = parse_arguments("--dc-ip", "192.0.2.10")

    assert arguments.dc_ip == "192.0.2.10"


def test_private_log_handler_uses_owner_only_permissions(tmp_path):
    log_path = tmp_path / "assessment.log"
    handler = _PrivateFileHandler(str(log_path))
    logger = logging.getLogger("atilkurt-test-private-log")
    logger.addHandler(handler)

    try:
        logger.warning("Synthetic test event")
    finally:
        logger.removeHandler(handler)
        handler.close()

    assert log_path.read_text(encoding="utf-8") == "Synthetic test event\n"
    assert os.stat(log_path).st_mode & 0o777 == 0o600


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symbolic links are unavailable")
def test_private_log_handler_does_not_follow_symbolic_links(tmp_path):
    target_path = tmp_path / "target.log"
    target_path.write_text("preserve", encoding="utf-8")
    link_path = tmp_path / "assessment.log"
    link_path.symlink_to(target_path)

    with pytest.raises(OSError):
        _PrivateFileHandler(str(link_path))

    assert target_path.read_text(encoding="utf-8") == "preserve"


def test_environment_password_is_removed_after_read(monkeypatch):
    from AtilKurt import resolve_password

    monkeypatch.setenv("ATILKURT_PASS", "unit-test-secret")
    arguments = parse_arguments()
    password, manager = resolve_password(arguments)
    try:
        assert password == "unit-test-secret"
        assert "ATILKURT_PASS" not in os.environ
    finally:
        manager.clear_password()
