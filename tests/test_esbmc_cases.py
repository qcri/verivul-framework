"""Expected verdicts of the probe programs under the label command (needs Docker
and the pinned image; skipped otherwise).  See docs/labelling_evidence.md.

    pytest tests/test_esbmc_cases.py -v
"""
import os
import shutil
import subprocess

import pytest

from src.agents.esbmc_verification import build_verification_command

CASES = os.path.join(os.path.dirname(__file__), 'esbmc_cases')
IMAGE = os.environ.get('ESBMC_IMAGE', 'esbmc:8.4')

EXPECTED = {
    # entry point and inputs
    'argv_strcpy.c': 'FAILED', 'argv_atoi_assert0.c': 'FAILED', 'argv1.c': 'SUCCESSFUL',
    'stdin_fgets_oob.c': 'FAILED', 'stdin_fgets_ok.c': 'SUCCESSFUL', 'stdin_fgets_uncapped.c': 'FAILED',
    'stdin_read_len_oob.c': 'FAILED', 'scanf1.c': 'SUCCESSFUL', 'fread1.c': 'SUCCESSFUL',
    'probes/in_getchar_oob.c': 'FAILED', 'probes/in_getchar_ok.c': 'SUCCESSFUL',
    'probes/in_scanf_index_oob.c': 'FAILED', 'probes/in_scanf_index_ok.c': 'SUCCESSFUL',
    'probes/in_read_posix_oob.c': 'FAILED', 'probes/in_fopen_fread_oob.c': 'FAILED',
    'probes/in_getenv_oob.c': 'FAILED', 'probes/in_getenv_ok.c': 'SUCCESSFUL',
    # allocator and leak model
    'malloc_field_align.c': 'SUCCESSFUL', 'probes/alloc_realloc_fail.c': 'SUCCESSFUL',
    'probes/alloc_calloc_strdup.c': 'SUCCESSFUL', 'probes/leak_local_lost.c': 'FAILED',
    'probes/leak_global_reachable.c': 'SUCCESSFUL', 'probes/leak_abort_path.c': 'SUCCESSFUL',
    'leak.c': 'FAILED',
    # strictness classes removed from the label
    'apdxj.c': 'SUCCESSFUL', 'shl1.c': 'SUCCESSFUL', 'shl2.c': 'SUCCESSFUL',
    'probes/chk_align_cast.c': 'SUCCESSFUL', 'probes/chk_align_list_walk.c': 'SUCCESSFUL',
    # genuine defects
    'uaf_kvm.c': 'FAILED', 'signed_overflow.c': 'FAILED', 'probes/chk_div_zero.c': 'FAILED',
    'probes/chk_double_free.c': 'FAILED', 'probes/chk_free_stack.c': 'FAILED',
    'probes/chk_stack_oob_write.c': 'FAILED', 'probes/chk_unsigned_wrap_used.c': 'FAILED',
    'probes/kind_bug_at_iter100.c': 'FAILED', 'probes/kind_input_loop_oob.c': 'FAILED',
    'probes/kind_input_bounded_loop_ok.c': 'SUCCESSFUL',
    'align_member_access.c': 'SUCCESSFUL',
}


def _docker_ok():
    if not shutil.which('docker'):
        return False
    return subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True).returncode == 0


needs_image = pytest.mark.skipif(not _docker_ok(), reason=f'docker image {IMAGE} not available')


def run_case(path, timeout=90):
    cmd = build_verification_command('c', '/work/source.c', container_timeout=timeout + 10)
    out = subprocess.run(
        ['docker', 'run', '--rm', '-v', f'{path}:/work/source.c:ro', '-w', '/work',
         '--entrypoint', 'bash', IMAGE, '-c', cmd],
        capture_output=True, text=True, timeout=timeout + 60)
    out = out.stdout + out.stderr
    if 'VERIFICATION SUCCESSFUL' in out and 'VERIFICATION FAILED' not in out:
        return 'SUCCESSFUL'
    if 'VERIFICATION FAILED' in out:
        return 'FAILED'
    return 'ERROR/TIMEOUT'


@needs_image
@pytest.mark.parametrize('case', sorted(EXPECTED))
def test_expected_verdict(case):
    assert run_case(os.path.join(CASES, case)) == EXPECTED[case]
