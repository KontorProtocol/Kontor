"""Compatibility entry point for the Rust historical semantic verifier."""

from provenance import _request


def verify(observations, root, expected_graphs=('first', 'second')):
    try:
        return _request(dict(operation="semantics", observations=observations,
                             root=str(root.absolute()), expected_graphs=list(expected_graphs)),
                        command="verify-node-evidence")
    except RuntimeError as error:
        raise ValueError(str(error)) from error
