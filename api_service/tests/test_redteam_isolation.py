import importlib


def test_redteam_module_importable():
    importlib.import_module("redteam")


def test_redteam_routes_importable():
    mod = importlib.import_module("redteam.routes")
    assert hasattr(mod, "router")
