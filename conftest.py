def pytest_addoption(parser):
    parser.addoption(
        "--nika-config",
        action="store",
        default=None,
        help="Config file for the e2e scan",
    )
