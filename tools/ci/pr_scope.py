"""Select ordinary PR checks without omitting shared or generated inputs."""

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tomllib

from stack_qualification_scope import BUILD_NAMES, changed_paths

REPRO_PREFIXES = (
    'native-contracts/', 'test-contracts/', 'core/stdlib/', 'core/macros/',
    'core/built-in-types/', 'core/numerics/', 'core/indexer-types/',
    'core/wit-validator/', 'core/bls-crypto/', 'core/kontor-sdk/',
    'core/kontor-sdk-wasm/', 'core/kontor-build/', 'core/vendor/',
    # wit-validator embeds these files outside its Cargo package directory.
    'core/indexer/src/runtime/wit/', 'core/contract/wit/',
    'sdk/src/component/', 'tools/native-crypto/',
)
REPRO_FILES = {
    'sdk/src/bindings.d.ts', 'sdk/package.json', 'sdk/package-lock.json',
    'tools/kontor', 'tools/build.json', 'tools/kontor-build.Dockerfile', '.dockerignore',
}
JOBS = ('rust', 'sdk', 'reproducible', 'docker_cache')


def build_metadata(path):
    parts = PurePosixPath(path).parts
    return (PurePosixPath(path).name in BUILD_NAMES
            or ('.cargo' in parts and PurePosixPath(path).name in {'config', 'config.toml'}))


def classify(path, docker_targets=()):
    if path.startswith('docs/') or ('/' not in path and path.endswith('.md')):
        return set()
    if path in docker_targets or build_metadata(path):
        return set(JOBS)
    if path.startswith('tools/ci/') or path == '.github/workflows/ci.yml':
        return set(JOBS)
    if path in {'Dockerfile', '.dockerignore', '.github/workflows/docker-cache.yml'} or path.startswith('.github/actions/setup-docker/'):
        return set(JOBS)
    if path.startswith(('core/', 'native-contracts/', 'test-contracts/')):
        selected = {'rust', 'sdk'}
        if path.startswith(REPRO_PREFIXES):
            selected.add('reproducible')
        # cargo fetch still discovers implicit targets and checks explicit paths.
        if (PurePosixPath(path).name in {'lib.rs', 'main.rs'}
                or any(part in PurePosixPath(path).parts for part in ('bin', 'examples', 'tests', 'benches'))):
            selected.add('docker_cache')
        return selected
    if path.startswith('sdk/'):
        return {'sdk', 'reproducible'} if path in REPRO_FILES or path.startswith('sdk/src/component/') else {'sdk'}
    if path.startswith('protocol-bundles/'):
        return {'rust', 'sdk', 'docker_cache'}
    # Unknown input classes deliberately retain the existing broad checks.
    return set(JOBS)


def validate_repro_dependencies(root):
    """A newly introduced local dependency must not silently escape the filter."""
    root = root.resolve()
    pending = [root / name for name in ('core/kontor-build', 'core/kontor-sdk-wasm')]
    for name in ('native-contracts', 'test-contracts'):
        workspace = root / name
        manifest = tomllib.loads((workspace / 'Cargo.toml').read_text())
        for member in manifest['workspace']['members']:
            pending.extend(workspace.glob(member))
    visited = set()
    while pending:
        package = pending.pop().resolve()
        if package in visited:
            continue
        visited.add(package)
        relative = package.relative_to(root).as_posix() + '/'
        if not relative.startswith(REPRO_PREFIXES):
            raise ValueError(f'uncovered artifact dependency: {relative}')
        manifest = tomllib.loads((package / 'Cargo.toml').read_text())
        workspace_path = manifest.get('package', {}).get('workspace')
        candidates = [package / workspace_path] if workspace_path else [package, *package.parents]
        workspace = None
        for candidate in candidates:
            file = candidate / 'Cargo.toml'
            if file.is_file():
                data = tomllib.loads(file.read_text())
                if 'workspace' in data:
                    workspace = (candidate, data['workspace'].get('dependencies', {}))
                    for patches in data.get('patch', {}).values():
                        for dependency in patches.values():
                            if isinstance(dependency, dict) and 'path' in dependency:
                                pending.append(candidate / dependency['path'])
                    break
        tables = [manifest, *manifest.get('target', {}).values()]
        for table in tables:
            for kind in ('dependencies', 'build-dependencies', 'dev-dependencies'):
                for name, dependency in table.get(kind, {}).items():
                    if not isinstance(dependency, dict):
                        continue
                    parent = package
                    if dependency.get('workspace'):
                        if workspace is None or name not in workspace[1]:
                            raise ValueError(f'unresolved workspace dependency: {name}')
                        parent, inherited = workspace
                        dependency = inherited[name]
                    if isinstance(dependency, dict) and 'path' in dependency:
                        pending.append(parent / dependency['path'])


def docker_target_paths(root):
    paths = set()
    for prefix in ('core', 'protocol-bundles'):
        for file in (root / prefix).rglob('Cargo.toml'):
            data = tomllib.loads(file.read_text())
            targets = [data.get('lib', {})]
            for name in ('bin', 'example', 'test', 'bench'):
                targets.extend(data.get(name, []))
            build = data.get('package', {}).get('build')
            if isinstance(build, str):
                targets.append({'path': build})
            for target in targets:
                if 'path' in target:
                    paths.add((file.parent / target['path']).resolve().relative_to(root.resolve()).as_posix())
    return paths


def select(event_name, event, root):
    try:
        validate_repro_dependencies(root)
        if event_name == 'workflow_dispatch':
            return {'jobs': dict.fromkeys(JOBS, True), 'reason': 'manual run', 'paths': []}
        paths = changed_paths(event_name, event, root)
        targets = docker_target_paths(root)
        selected = set().union(*(classify(path, targets) for path in paths))
        return {'jobs': {name: name in selected for name in JOBS}, 'reason': 'changed inputs', 'paths': paths}
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        return {'jobs': dict.fromkeys(JOBS, True), 'reason': f'cannot establish scope: {error}', 'paths': []}


def main():
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    result = select(os.environ['GITHUB_EVENT_NAME'], event, Path.cwd())
    print(json.dumps(result, indent=2))
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        for name, required in result['jobs'].items():
            output.write(f'{name}={str(required).lower()}\n')


if __name__ == '__main__':
    main()
