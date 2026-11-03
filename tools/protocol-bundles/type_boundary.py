"""Compatibility calls into Rust interface controls until the builder migration."""

import os
from pathlib import Path
import sys

from provenance import _request


def _interface(operation, **values):
    env = dict(os.environ)
    if "--offline" in sys.argv[1:]:
        env["CARGO_NET_OFFLINE"] = "true"
    return _request(dict(operation=operation, **values), command="interface", env=env)


def _probes(values):
    return {name: (expected, source) for name, expected, source in values}


_catalog = _interface("catalog")
PROBES = _probes(_catalog["probes"])
ADAPTED_EXECUTOR_PROBES = _probes(_catalog["adapted"])
CONSENSUS_PROBES = _probes(_catalog["consensus"])
ADAPTER_TESTS = _catalog["adapter_tests"]
del _catalog


def probes_for(graphs):
    selected = _probes(_interface("probes", graphs=graphs))
    return next(probes for probes in (PROBES, ADAPTED_EXECUTOR_PROBES, CONSENSUS_PROBES)
                if probes == selected)


def check_diagnostics(returncode, text, expected):
    _interface("diagnostics", returncode=returncode, text=text, expected=expected)


def inputs_for(graphs, check_files):
    value = _interface("inputs", graphs=graphs, check_files=check_files, cwd=str(Path.cwd()))
    return value["arguments"], value["inputs"]


def verify_report(directory, binding, graphs, target):
    _interface("verify_report", directory=str(directory.absolute()), binding=binding,
               graphs=graphs, target=target)


def verify(graphs, target, env, output):
    return _interface("verify", graphs=graphs, target=target, env=env,
                      output=str(output.absolute()), cwd=str(Path.cwd()))


def verify_node_adapter(root, graphs, target, env, output):
    return _interface("verify_adapter", root=str(root.absolute()), graphs=graphs, target=target,
                      env=env, output=str(output.absolute()), cwd=str(Path.cwd()))


def adapter_tests_passed(returncode, output):
    return _interface("adapter_passed", returncode=returncode, output=output)


def verify_node_adapter_report(directory, binding, graphs):
    _interface("verify_adapter_report", directory=str(directory.absolute()), binding=binding,
               graphs=graphs)
