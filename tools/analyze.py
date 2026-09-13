#!/usr/bin/env python3
"""Run source scanners against a configured Meson build without touching hardware."""

import argparse
import concurrent.futures
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def production_commands(build):
    seen = set()
    commands = []
    for entry in json.loads((build / 'compile_commands.json').read_text()):
        source = (Path(entry['directory']) / entry['file']).resolve()
        if source in seen or 'tests' in source.relative_to(ROOT).parts:
            continue
        seen.add(source)
        commands.append((entry, source))
    return commands


def analyze_clang(item, timeout):
    entry, source = item
    args = entry.get('arguments') or shlex.split(entry['command'])
    flags = []
    skip = False
    for arg in args[1:]:
        if skip:
            skip = False
        elif arg in ('-o', '-MF', '-MQ', '-MT'):
            skip = True
        elif arg not in ('-c', '-MD', '-MMD') and not arg.endswith(('.c', '.cpp')):
            flags.append(arg)
    compiler = 'clang++' if source.suffix == '.cpp' else 'clang'
    command = [compiler, '--analyze', '-Xanalyzer', '-analyzer-output=text',
               *flags, '-fno-color-diagnostics', str(source)]
    try:
        result = subprocess.run(command, cwd=entry['directory'],
                                capture_output=True, text=True, timeout=timeout)
        output = result.stdout + result.stderr
        failed = result.returncode != 0 or 'warning:' in output
    except subprocess.TimeoutExpired:
        failed, output = True, f'Analysis exceeded {timeout} seconds\n'
    return source, failed, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path, help='Configured Meson build directory')
    parser.add_argument('--tool', choices=['all', 'clang', 'cppcheck', 'shellcheck'], default='all')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--timeout', type=int, default=180, help='Clang time limit per source file')
    parser.add_argument('--output', type=Path, default=ROOT / 'build-analysis')
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout < 1:
        parser.error('jobs and timeout must be positive')
    build = args.build.resolve()
    selected = ['shellcheck', 'cppcheck', 'clang'] if args.tool == 'all' else [args.tool]
    for program in selected + (['clang++'] if 'clang' in selected else []):
        if not shutil.which(program):
            parser.error(f'Missing scanner: {program}')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    failed = False
    commands = production_commands(build) if any(t != 'shellcheck' for t in selected) else []
    for tool in selected:
        logfile = output / f'{tool}.log'
        if tool == 'clang':
            with logfile.open('w') as log, concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = [pool.submit(analyze_clang, item, args.timeout) for item in commands]
                for future in concurrent.futures.as_completed(futures):
                    source, issue, text = future.result()
                    log.write(f'FILE {source.relative_to(ROOT)}\n{text}\n')
                    failed |= issue
                    if issue:
                        print(f'clang: review {source.relative_to(ROOT)}', flush=True)
        elif tool == 'cppcheck':
            database = output / 'production-commands.json'
            database.write_text(json.dumps([entry for entry, _ in commands], indent=2))
            command = [tool, f'--project={database}', '--platform=unix64',
                       '-D__x86_64__', '-D__linux__', '--enable=warning,performance,portability',
                       '--inline-suppr', '--check-level=exhaustive', '--template=gcc',
                       '--error-exitcode=1', '-j', str(args.jobs),
                       f'--output-file={logfile}']
            with (output / 'cppcheck-progress.log').open('w') as progress:
                result = subprocess.run(command, cwd=ROOT, stdout=progress, stderr=progress)
            failed |= result.returncode != 0
        else:
            scripts = sorted((ROOT / 'scripts').iterdir()) + [ROOT / 'libtudor/download_driver.sh']
            with logfile.open('w') as log:
                result = subprocess.run([tool, '--severity=warning', *map(str, scripts)],
                                        cwd=ROOT, stdout=log, stderr=log)
            failed |= result.returncode != 0
        print(f'{tool}: {logfile}', flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
