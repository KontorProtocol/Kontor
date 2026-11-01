"""Select linked-node builds separately from inexpensive evidence checks."""

import json
import os
from pathlib import Path
import subprocess

from stack_qualification_scope import changed_paths, evidence_only, profile_policy, relevant


def select(event_name, event, root):
    if event_name == 'workflow_dispatch':
        return {'required': True, 'controls': True, 'reason': 'manual qualification', 'paths': []}
    try:
        paths = changed_paths(event_name, event, root)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        return {'required': True, 'controls': True,
                'reason': f'cannot establish change scope: {type(error).__name__}', 'paths': []}
    selected = sorted(path for path in paths if not evidence_only(path) and (
        relevant(path) or path.startswith('core/indexer/')
        or path == 'tools/ci/bundle_qualification_scope.py'
    ))
    return {'required': bool(selected), 'controls': bool(selected) or any(evidence_only(path) for path in paths),
            'paths': selected,
            'reason': 'node or build inputs changed' if selected else 'no linked-node inputs changed'}


def main():
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    event_name = os.environ['GITHUB_EVENT_NAME']
    result = select(event_name, event, Path.cwd())
    result['profile_policy'] = profile_policy(event_name, event)
    print(json.dumps(result, indent=2))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write(f"required={str(result['required']).lower()}\n")
        output.write(f"controls={str(result['controls']).lower()}\n")
        output.write(f"profile_policy={result['profile_policy']}\n")


if __name__ == '__main__':
    main()
