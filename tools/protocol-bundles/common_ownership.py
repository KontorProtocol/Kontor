"""Compatibility calls into Rust shared ownership rules until the builder migration."""

import json
from pathlib import Path

from provenance import _request


def _shared(operation, **values):
    return _request(dict(operation=operation, working_directory=str(Path.cwd()), **values),
                    command="audit-shared")


def references(path):
    return {name: set(kinds) for name, kinds in _shared("references", path=str(path)).items()}


def runtime_paths(executable, kind="proof"):
    return _shared("runtime_paths", executable=str(executable), kind=kind)


def platform_owners(executable, candidates, kind="proof"):
    return tuple(_shared("platform_owners", executable=str(executable), candidates=sorted(candidates), kind=kind))


def reject_common_shadow(graph, names, common):
    _shared("reject_shadow", graph=graph["graph"], names=sorted(names), owners=sorted(common), node=False)


def reject_node_shadow(graph, names, node):
    _shared("reject_shadow", graph=graph["graph"], names=sorted(names), owners=sorted(node), node=True)


def graph_references(graph, index, sets):
    result = _shared("graph_references", graph=graph, index=index, sets=list(map(sorted, sets)))
    return tuple(map(set, result))


def linker_owners(executable):
    return _shared("linker_owners", executable=str(executable))


def reject_unowned_references(graph, names, refs, common, platform, optional, linker, compiler=None):
    _shared("reject_unowned", graph=graph["graph"], names=sorted(names), refs=sorted(refs),
            common=sorted(common), platform=sorted(platform), optional=sorted(optional),
            linker=sorted(linker), compiler=sorted(compiler or {}))


def verify(graphs, sets, host_objects, executable, env, output, kind="proof",
           node_objects=(), compiler_objects=()):
    result = _shared("verify", graphs=graphs, sets=list(map(sorted, sets)),
                     host_objects=list(map(str, host_objects)), executable=str(executable), env=env,
                     kind=kind, node_objects=list(map(str, node_objects)),
                     compiler_objects=list(map(str, compiler_objects)))
    (output / "common-reference-ownership.json").write_text(json.dumps(result["report"], sort_keys=True) + "\n")
    if result["node_report"] is not None:
        (output / "node-input-ownership.json").write_text(json.dumps(result["node_report"], sort_keys=True) + "\n")
    return result["common"], result["node"]
