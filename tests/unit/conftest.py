import pathlib

_UNIT_DIR = pathlib.Path(__file__).parent


def pytest_collection_modifyitems(items):
    for item in items:
        path = pathlib.Path(getattr(item, "path", "") or item.fspath)
        try:
            path.relative_to(_UNIT_DIR)
        except ValueError:
            continue
        item.add_marker("unit")
