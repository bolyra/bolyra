collect_ignore_glob = ["experiments/*", "winners/*"]


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: tests that invoke Claude CLI (slow, require login)"
    )
