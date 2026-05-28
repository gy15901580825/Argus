import importlib


def test_redteam_module_importable():
    mod = importlib.import_module("orchestrator.redteam")
    assert mod is not None


def test_redteam_dispatcher_importable():
    mod = importlib.import_module("orchestrator.redteam.dispatcher")
    assert hasattr(mod, "Dispatcher")
