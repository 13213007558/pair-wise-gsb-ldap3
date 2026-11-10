"""Load the hyphenated ``security-review`` directory as importable modules."""

import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


safe_ldap = _load("safe_ldap")
ber_inspect = _load("ber_inspect")
