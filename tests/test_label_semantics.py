"""Guards on the flags and the CWE mapping that together define a label.

A label in this corpus is only meaningful relative to the ESBMC configuration
that produced it, so a silent change to either the flag list or the
violation -> CWE mapping changes what VULNERABLE and SAFE mean without changing
any code that looks like labelling code.  These tests pin the decisions and
record why each one was made, so a future change has to be deliberate.

The ESBMC cases need an `esbmc` binary (>= 8.4) on PATH or in $ESBMC_BIN and are
skipped when one is not available.

    pytest tests/test_label_semantics.py -v
"""
import os
import re
import shutil
import subprocess
import tempfile

import pytest

from src.agents.esbmc_verification import (
    build_verification_command,
    cwes_from_esbmc_annotation,
    infer_cwes_from_esbmc_log,
)

ESBMC = os.environ.get('ESBMC_BIN') or shutil.which('esbmc')
needs_esbmc = pytest.mark.skipif(ESBMC is None,
                                 reason='no esbmc binary (set ESBMC_BIN)')


def _flags():
    cmd = build_verification_command('c', '__SRC__')
    parts = cmd.split('&&', 1)[1].split()
    return parts[1:]


# ---------------------------------------------------------------------------
# Flag list
# ---------------------------------------------------------------------------

def test_unsigned_overflow_check_is_not_enabled():
    """Unsigned wraparound is defined behaviour in C.

    Enabling the check also mis-encodes `1u << k` as signed and fires inside
    ESBMC's own fread model, neither of which is a property of the program.
    """
    assert '--unsigned-overflow-check' not in _flags()


def test_signed_overflow_check_is_enabled():
    """Signed overflow is undefined behaviour and must stay checked."""
    assert '--overflow-check' in _flags()


def test_unlimited_scanf_check_is_not_disabled():
    """--no-unlimited-scanf-check turns genuine unbounded writes into SAFE.

    Measured on 8.4: it flips scanf("%s", buf8) and sscanf(line, "%s", buf8)
    from FAILED to SUCCESSFUL.  The artefact it was meant to suppress (a numeric
    conversion such as scanf("%u", &x)) is already gone in 8.4.
    """
    assert '--no-unlimited-scanf-check' not in _flags()


def test_allocation_failure_paths_are_not_labels():
    """Both allocator switches are needed."""
    flags = _flags()
    assert '--force-malloc-success' in flags
    assert '--force-realloc-success' in flags


def test_leak_check_matches_leaksanitizer_semantics():
    flags = _flags()
    assert '--memory-leak-check' in flags
    assert '--no-reachable-memory-leak' in flags
    assert '--no-abnormal-memory-leak' in flags


def test_alignment_is_not_checked():
    assert '--no-align-check' in _flags()


def test_witness_and_sarif_outputs():
    """ESBMC appends .graphml/.yml itself; the stem must not carry a suffix."""
    flags = _flags()
    assert flags[flags.index('--witness-output') + 1] == '/work/witness'
    assert '--sarif-output' in flags


def test_multi_property_is_never_used():
    """--multi-property with --witness-output crashes ESBMC 8.4 mid-report."""
    assert '--multi-property' not in _flags()


def test_argv_is_backed_with_real_strings():
    """Without this, argv[i] is NULL for every unbacked i.

    Any program that reads argument *content* then fails on the entry-point
    model rather than on its own logic.  6 covers 99.6% of the argv-reading
    programs in the corpus.
    """
    flags = _flags()
    assert '--argv-max-args' in flags
    assert int(flags[flags.index('--argv-max-args') + 1]) >= 6
    assert '--argv-max-strlen' in flags
    assert int(flags[flags.index('--argv-max-strlen') + 1]) >= 8


def test_esbmc_budget_leaves_room_to_report():
    """ESBMC must give up before the container wait kills it and discards output."""
    from src.agents.esbmc_verification import esbmc_budget
    timeout, _mem = esbmc_budget(600)
    assert int(timeout.rstrip('s')) < 600


# ---------------------------------------------------------------------------
# CWE mapping
# ---------------------------------------------------------------------------

def test_esbmc_annotation_wins_over_the_regex_catalogue():
    log = ("Violated property:\n"
           "  file x.c line 5 column 30 function main\n"
           "  array bounds violated: array `a' upper bound\n"
           "  CWE: CWE-121, CWE-125, CWE-787\n")
    assert cwes_from_esbmc_annotation(log) == ['CWE-121', 'CWE-125', 'CWE-787']
    assert infer_cwes_from_esbmc_log(log) == ['CWE-121', 'CWE-125', 'CWE-787']


def test_bounds_violation_is_not_recorded_as_a_read_only():
    """ESBMC does not report direction, so a write must not be filed as CWE-125.

    This is what the ordered catalogue used to do: `array bounds violated`
    matched the out-of-bounds *read* rule first and stopped there.
    """
    log = ("Violated property:\n  file x.c line 1 column 1 function main\n"
           "  array bounds violated: array `a' upper bound\n")
    cwes = infer_cwes_from_esbmc_log(log)
    assert 'CWE-787' in cwes, cwes


@pytest.mark.parametrize('desc,expected', [
    ('dereference failure: NULL pointer', 'CWE-476'),
    ('dereference failure: invalidated dynamic object', 'CWE-416'),
    ('dereference failure: forgotten memory: dynamic_1_arr', 'CWE-401'),
    ('dereference failure: invalid pointer freed', 'CWE-590'),
    ('arithmetic overflow on add', 'CWE-190'),
    ('arithmetic overflow on sub', 'CWE-191'),
    ('buffer overflow on scanf', 'CWE-120'),
    ('division by zero', 'CWE-369'),
])
def test_fallback_catalogue_for_unannotated_logs(desc, expected):
    """Logs without a CWE line still need the catalogue."""
    log = f"Violated property:\n  file x.c line 1 column 1 function main\n  {desc}\n"
    assert expected in infer_cwes_from_esbmc_log(log)


def test_no_cwes_for_a_clean_run():
    assert infer_cwes_from_esbmc_log('VERIFICATION SUCCESSFUL') == []
    assert infer_cwes_from_esbmc_log('') == []


# ---------------------------------------------------------------------------
# End to end: the flag list must keep genuine defects detected
# ---------------------------------------------------------------------------

CONTROLS = {
    'uaf': '#include <stdlib.h>\nint main(void){int*p=malloc(16);p[0]=1;free(p);'
           'return p[0];}\n',
    'null_deref': 'int main(void){int*p=0;int q=3;if(q>2)p=0;return *p;}\n',
    'leak': '#include <stdlib.h>\nint main(void){char*p=malloc(64);p[0]=1;'
            'return p[0];}\n',
    'oob_write': 'int main(void){int a[4];int i;for(i=0;i<=4;i++)a[i]=i;'
                 'return a[0];}\n',
    'unbounded_scanf': '#include <stdio.h>\nint main(void){char s[8];'
                       'if(scanf("%s",s)!=1)return 1;return s[0];}\n',
    'argv_strcpy': '#include <string.h>\nint main(int argc,char**argv){char b[4];'
                   'if(argc<2)return 1;strcpy(b,argv[1]);return b[0];}\n',
    'signed_overflow': '#include <stdio.h>\nint add(int a,int b){return a+b;}\n'
                       'int main(void){int x,y;if(scanf("%d %d",&x,&y)!=2)return 1;'
                       'return add(x,y);}\n',
}

SAFE = {
    # bounded scanf: correct, and must not be reported
    'bounded_scanf': '#include <stdio.h>\nint main(void){char s[8];'
                     'if(scanf("%7s",s)!=1)return 1;return s[0];}\n',
    # reads argv content but stays in bounds
    'argv_bounded': '#include <string.h>\n#include <stdio.h>\n'
                    'int main(int argc,char**argv){char b[64];if(argc<2)return 1;'
                    'snprintf(b,sizeof b,"%s",argv[1]);return b[0];}\n',
    # unsigned wraparound alone is defined behaviour
    'unsigned_wrap': '#include <stdio.h>\nint main(void){unsigned x;'
                     'if(scanf("%u",&x)!=1)return 1;unsigned y=x*3u+7u;'
                     'printf("%u\\n",y);return 0;}\n',
}


def _verify(source: str) -> str:
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'source.c')
        with open(path, 'w') as fh:
            fh.write(source)
        cmd = build_verification_command('c', path)
        inner = cmd.split('&&', 1)[1].strip().split()
        flags = [a for a in inner[1:] if a not in ('--input-file', path)]
        # the witness path is a container path; redirect it into the temp dir
        # (ESBMC appends its own extension, so /dev/null does not work here)
        flags = [os.path.join(d, 'witness') if a == '/work/witness.graphml' else a
                 for a in flags]
        # keep the suite quick; these are all tiny programs
        for i, a in enumerate(flags):
            if a == '--timeout':
                flags[i + 1] = '120s'
        out = subprocess.run([ESBMC] + flags + ['--input-file', path],
                             capture_output=True, text=True, timeout=180)
        text = out.stdout + out.stderr
    if 'VERIFICATION FAILED' in text:
        return 'FAILED'
    if 'VERIFICATION SUCCESSFUL' in text:
        return 'SUCCESSFUL'
    return 'INCONCLUSIVE'


@needs_esbmc
@pytest.mark.parametrize('name', sorted(CONTROLS))
def test_genuine_defects_stay_detected(name):
    assert _verify(CONTROLS[name]) == 'FAILED'


@needs_esbmc
@pytest.mark.parametrize('name', sorted(SAFE))
def test_correct_programs_are_not_reported(name):
    assert _verify(SAFE[name]) == 'SUCCESSFUL'


@needs_esbmc
def test_esbmc_annotates_cwes():
    """The annotated path is only preferred because the binary supplies it."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'source.c')
        with open(path, 'w') as fh:
            fh.write(CONTROLS['uaf'])
        cmd = build_verification_command('c', path)
        inner = cmd.split('&&', 1)[1].strip().split()
        flags = [a for a in inner[1:] if a not in ('--input-file', path)]
        # the witness path is a container path; redirect it into the temp dir
        # (ESBMC appends its own extension, so /dev/null does not work here)
        flags = [os.path.join(d, 'witness') if a == '/work/witness.graphml' else a
                 for a in flags]
        out = subprocess.run([ESBMC] + flags + ['--input-file', path],
                             capture_output=True, text=True, timeout=180)
    cwes = cwes_from_esbmc_annotation(out.stdout + out.stderr)
    assert 'CWE-416' in cwes, f'no CWE annotation from {ESBMC}: {cwes}'


def test_unsupported_python_function_is_not_a_vulnerability():
    from src.agents.esbmc_agent import get_verdict
    from src.db.models import Label, Status
    log = ("[Counterexample]\n\nState 1 file /work/source.py line 198 column 11 function main thread 0\n"
           "----------------------------------------------------\nViolated property:\n"
           "  file /work/source.py line 198 column 11 function main\n  Unsupported function 'read' is reached\n  0\n\n"
           "VERIFICATION FAILED\n")
    assert get_verdict(log, 1) == (Status.VERIFICATION_ERROR, Label.UNKNOWN)
    real = log.replace("Unsupported function 'read' is reached", "array bounds violated")
    assert get_verdict(real, 1) == (Status.VERIFICATION_SUCCESS, Label.VULNERABLE)
