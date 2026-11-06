"""The compile-stage ESBMC front-end check (needs Docker and the pinned image for the live cases)."""
import os
import shutil
import subprocess
import tempfile

import pytest

from src.agents.esbmc_verification import FRONTEND_CHECK_LANGUAGES, build_frontend_check_command

IMAGE = os.environ.get('ESBMC_IMAGE', 'esbmc:8.4')


def test_command_only_runs_the_front_end():
    for lang, ext in (('c', 'c'), ('cpp', 'cpp'), ('python', 'py')):
        cmd = build_frontend_check_command(lang, f'/work/source.{ext}')
        assert '--goto-functions-only' in cmd and f'/work/source.{ext}' in cmd
        assert 'k-induction' not in cmd and '--unwind' not in cmd
    assert build_frontend_check_command('kotlin', '/work/source.kt') is None
    assert set(FRONTEND_CHECK_LANGUAGES) == {'c', 'cpp', 'python'}


def _docker_ok():
    return bool(shutil.which('docker')) and subprocess.run(
        ['docker', 'image', 'inspect', IMAGE], capture_output=True).returncode == 0


CASES = [
    ('cpp', 'cpp', '#include <cstring>\nint main(){ return (int)std::strlen("a"); }\n', False),
    ('cpp', 'cpp', '#include <string.h>\nint main(void){ return (int)strlen("a"); }\n', True),
    ('python', 'py', 'import sys\nassert 1 + 1 == 2\n', False),
    ('python', 'py', 'import math\nassert int(math.sqrt(4)) == 2\n', True),
    ('c', 'c', '#include <stdio.h>\nint main(void){ puts("x"); return 0; }\n', True),
]


@pytest.mark.skipif(not _docker_ok(), reason=f'docker image {IMAGE} not available')
@pytest.mark.parametrize('lang,ext,code,accepted', CASES)
def test_front_end_verdict(lang, ext, code, accepted):
    td = tempfile.mkdtemp(prefix='verivul-fetest-')
    try:
        os.chmod(td, 0o755)
        with open(os.path.join(td, f'source.{ext}'), 'w') as f:
            f.write(code)
        cmd = build_frontend_check_command(lang, f'/work/source.{ext}')
        rc = subprocess.run(['docker', 'run', '--rm', '-v', f'{td}:/work:ro', '-w', '/work',
                             '--entrypoint', 'bash', IMAGE, '-c', cmd],
                            capture_output=True, text=True, timeout=120).returncode
        assert (rc == 0) == accepted
    finally:
        shutil.rmtree(td, ignore_errors=True)
