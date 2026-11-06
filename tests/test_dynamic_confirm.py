import base64
import os
import shutil
import subprocess

import pytest

from src.utils.confirm_runner import channels, classify
from src.utils.dynamic_confirm import compare, confirm

IMAGE = os.environ.get('ESBMC_IMAGE', 'esbmc:8.4')
CASES = os.path.join(os.path.dirname(__file__), 'esbmc_cases')


def _image_ok():
    return bool(shutil.which('docker')) and subprocess.run(
        ['docker', 'image', 'inspect', IMAGE], capture_output=True).returncode == 0


needs_image = pytest.mark.skipif(not _image_ok(), reason=f'docker image {IMAGE} not available')


def run(finding=None, compiled=True):
    return {'compiled': compiled, 'finding': finding}


def test_exact_match_needs_class_and_line():
    f = {'kind': 'heap-use-after-free', 'function': 'g', 'line': 30}
    assert compare('VULNERABLE', 'memory-safety:lifetime', 'g', 30, run(f)) == 'confirmed_exact'
    assert compare('VULNERABLE', 'memory-safety:lifetime', 'g', 99, run(f)) == 'confirmed_function'
    assert compare('VULNERABLE', 'memory-safety:lifetime', 'h', 99, run(f)) == 'confirmed_class'


def test_other_defect_and_not_reproduced():
    f = {'kind': 'heap-buffer-overflow', 'function': 'g', 'line': 3}
    assert compare('VULNERABLE', 'resource-leak', 'g', 3, run(f)) == 'other_defect'
    assert compare('VULNERABLE', 'resource-leak', 'g', 3, run(None)) == 'not_reproduced'


def test_safe_outcomes():
    assert compare('SAFE', None, None, None, run(None)) == 'no_crash_found'
    assert compare('SAFE', None, None, None, run({'kind': 'segv'})) == 'counterexample_found'


def test_compile_error_is_reported():
    assert compare('SAFE', None, None, None, run(compiled=False)) == 'compile_error'


def test_out_of_scope_ub_and_allocation_size_are_not_findings():
    nonnull = "/work/source.c:46:21: runtime error: null pointer passed as argument 1, which is declared to never be null"
    assert classify(98, nonnull) is None
    huge = "==1==ERROR: AddressSanitizer: requested allocation size 0xffffffff exceeds maximum supported size"
    assert classify(99, huge) is None


def test_sanitizer_reports_are_classified():
    asan = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
            "    #0 0x1 in vcpu_update_clock /work/source.c:30:9\n")
    assert classify(99, asan) == ('heap-use-after-free', 'vcpu_update_clock', 30)
    assert classify(99, "==1==ERROR: AddressSanitizer: attempting double-free on 0x1\n    #1 0x2 in main /work/source.c:2:1")[0] \
        == 'attempting double-free'
    assert classify(98, "/work/source.c:2:61: runtime error: signed integer overflow: 1 * 2 cannot be represented")[0] == 'signed-overflow'
    assert classify(0, asan) is None


def test_channels_and_environment_apis():
    code = 'int main(void){ char b[8]; FILE*f=fopen("cfg.bin","rb"); const char*e=getenv("HOME"); time(0); fgets(b,8,stdin); }'
    ch = channels(code)
    assert ch['stdin'] and ch['env'] == ['HOME'] and ch['files'] == ['cfg.bin']
    assert 'time' in ch['env_apis'] and 'fopen' in ch['env_apis']


@needs_image
@pytest.mark.parametrize('case,label,cat,expected', [
    ('stdin_fgets_oob.c', 'VULNERABLE', 'memory-safety:bounds', {'confirmed_exact', 'confirmed_function', 'confirmed_class'}),
    ('uaf_kvm.c', 'VULNERABLE', 'memory-safety:lifetime', {'confirmed_exact', 'confirmed_function', 'confirmed_class'}),
    ('leak.c', 'VULNERABLE', 'resource-leak', {'confirmed_exact', 'confirmed_function', 'confirmed_class'}),
    ('stdin_fgets_ok.c', 'SAFE', None, {'no_crash_found'}),
    ('probes/leak_global_reachable.c', 'SAFE', None, {'no_crash_found'}),
    ('probes/leak_abort_path.c', 'SAFE', None, {'no_crash_found'}),
    ('probes/alloc_realloc_fail.c', 'SAFE', None, {'no_crash_found'}),
])
def test_confirmation_on_probe_programs(case, label, cat, expected):
    code = open(os.path.join(CASES, case)).read()
    res = confirm(code, 'c', label, cat, budget=30, image=IMAGE)
    assert res['result'] in expected
    if label == 'VULNERABLE':
        f = res['finding']
        assert 'Sanitizer' in f['report'] or 'runtime error' in f['report']
        assert base64.b64decode(f['input_b64']) is not None and f['input_len'] >= 0


def test_cpp_frames_with_spaces_name_the_function():
    asan = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
            "    #0 0x1 in __interceptor_memcpy ../../src/asan.cpp:1\n"
            "    #1 0x2 in computeChecksum(std::vector<unsigned char, std::allocator<unsigned char> > const&, unsigned int) /work/source.cpp:94:5\n"
            "    #2 0x3 in main /work/source.cpp:185:3\n")
    assert classify(99, asan) == ('heap-buffer-overflow', 'computeChecksum', 94)
    assert classify(99, asan.replace('computeChecksum(std::vector', 'FrameProcessor::~FrameProcessor(std::vector'))[1] == '~FrameProcessor'


def test_asan_allocation_failure_warning_is_an_artefact():
    assert classify(1, "WARNING: AddressSanitizer failed to allocate 0xfffff bytes\n==1==ERROR: AddressSanitizer: SEGV") is None


def test_shl_overflow_is_matched_as_a_shift():
    from src.utils.provenance import category
    log = ("Violated property:\n  file /work/source.c line 29 column 5 function read_u32\n"
           "  arithmetic overflow on shl\n  !overflow(\"shl\", x, 24)\n\nVERIFICATION FAILED")
    assert category('VULNERABLE', log)['category'] == 'ub:shift'
    f = {'kind': 'shift', 'function': 'read_u32', 'line': 29}
    assert compare('VULNERABLE', 'ub:shift', 'read_u32', 29, run(f)) == 'confirmed_exact'
