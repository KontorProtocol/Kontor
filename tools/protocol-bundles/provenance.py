"""Compatibility calls into Rust provenance tooling until the builder migration."""

from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=4)
def _tool_path(environment):
    root = Path(__file__).resolve().parents[2]
    return subprocess.check_output([str(root / "tools/kontor"), "tool-path"],
                                   cwd=root, env=dict(environment), text=True).strip()


def _request(request, *, env=None):
    env = dict(os.environ) if env is None else env
    root = Path(__file__).resolve().parents[2]
    tool = env.get("KONTOR_BUILD_TOOL") or _tool_path(tuple(sorted(env.items())))
    result = subprocess.run([tool, "provenance"], input=json.dumps(request),
                            capture_output=True, text=True, cwd=root, env=env)
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return json.loads(result.stdout)


def retained_trees():
    return tuple(_request(dict(operation="retained_trees")))


def check_source_policy(root, data, *, kind="proof", env=None):
    return _request(dict(operation="source_policy", root=str(root.absolute()), data=data, kind=kind), env=env)


def proc_macro_hashes(graphs, options, env, output):
    return _request(dict(operation="proc_macro_hashes", graphs=graphs, options=options, env=env,
                         output=str(output.absolute()), working_directory=str(Path.cwd())), env=env)


def retained_sources(root):
    return _request(dict(operation="retained_sources", root=str(root.absolute())))


def node_sources(root):
    return _request(dict(operation="node_sources", root=str(root.absolute())))


def consensus_sources(root):
    return _request(dict(operation="consensus_sources", root=str(root.absolute())))


def repository_sources(root, kind):
    return _request(dict(operation="repository_sources", root=str(root.absolute()), kind=kind))


def local_source_files(directory, root):
    paths = _request(dict(operation="local_files", directory=str(directory.absolute()), root=str(root.absolute())))
    return (Path(path) for path in paths)


def package_sources(directory, *, root=None):
    return _request(dict(operation="package_sources", directory=str(directory.absolute()),
                         root=str(root.absolute()) if root is not None else None))


def source_inputs(root, data, *, kind="proof", tool_root=None, env=None):
    return _request(dict(operation="source_inputs", root=str(root.absolute()), data=data, kind=kind,
                         tool_root=str(tool_root.absolute()) if tool_root is not None else None,
                         cargo_home=str(Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).absolute())), env=env)


def locked_packages(lock):
    return _request(dict(operation="locked_packages", lock=str(lock.absolute())))


def tools(env, target):
    return _request(dict(operation="toolchain", working_directory=str(Path.cwd()), env=env, target=target), env=env)


def runtime_libraries(executable, env, graphs):
    return _request(dict(operation="runtime_libraries", working_directory=str(Path.cwd()), executable=str(executable), env=env, graphs=graphs), env=env)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
