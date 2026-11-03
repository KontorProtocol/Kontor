"""Compatibility calls into Rust node transition evidence verification."""

from provenance import _request


def _verify(operation, result, **values):
    try:
        return _request(dict(operation=operation, result=result, **values), command="verify-node-evidence")
    except RuntimeError as error:
        raise ValueError(str(error)) from error


def verify_transition(result, root):
    return _verify("transition", result, root=str(root.absolute()))


def transition_semantics(result, root):
    return _verify("transition", result, root=str(root.absolute()), semantic_only=True)


def verify_recovery(result):
    return _verify("recovery", result)


def verify_authorization(result):
    return _verify("authorization", result)


def verify_join(result):
    return _verify("join", result)
