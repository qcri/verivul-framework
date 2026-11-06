from src.utils.program_guards import check_program, leakage_hits

CLEAN = '''#include <stdio.h>
#include <string.h>
struct frame { unsigned short len; unsigned char body[64]; };
static int decode(struct frame *f, const unsigned char *buf, size_t n) {
    if (n < 2) return -1;
    f->len = (unsigned short)(buf[0] | (buf[1] << 8));
    memcpy(f->body, buf + 2, f->len);
    return 0;
}
int main(void) { unsigned char buf[128]; struct frame f; size_t n = fread(buf, 1, sizeof buf, stdin); return decode(&f, buf, n); }
'''


def test_clean_program_passes():
    assert check_program(CLEAN, 'c') == []


def test_argv_is_rejected():
    code = CLEAN.replace('int main(void)', 'int main(int argc, char **argv)')
    assert 'reads argc/argv' in check_program(code, 'c')


def test_intrinsics_are_rejected():
    assert 'uses verifier intrinsics' in check_program(CLEAN + '\nvoid g(int x){ __ESBMC_assume(x > 0); }', 'c')


def test_threads_are_rejected():
    assert 'uses threads or fork' in check_program('#include <pthread.h>\n' + CLEAN, 'c')


def test_leakage_in_identifier_comment_and_string():
    code = CLEAN.replace('static int decode', '/* trigger the overflow here */\nstatic int decode')
    code = code.replace('struct frame f;', 'struct frame f; int is_vulnerable = 0; (void)is_vulnerable;')
    hits = leakage_hits(code)
    assert 'overflow' in hits and 'vulnerable' in hits
    assert any(r.startswith('label leakage') for r in check_program(code, 'c'))


def test_prefix_and_suffix_are_not_leakage():
    assert leakage_hits('int prefix_len; int suffix; char fixture[4];') == []


def test_non_c_languages_are_not_checked():
    assert check_program('def main(argv): pass', 'python') == []


def test_rules_can_be_disabled():
    code = CLEAN.replace('int main(void)', 'int main(int argc, char **argv)')
    assert check_program(code, 'c', {'reject_argv': False}) == []


def test_file_and_environment_input_is_rejected():
    for src in ('int main(void){ FILE *f = fopen(path, "rb"); return 0; }',
                'int main(void){ const char *p = getenv("LOGFILE"); return 0; }',
                'int main(void){ std::ifstream in("data.bin"); return 0; }'):
        assert any('stdin' in r for r in check_program(src, 'c'))
    assert check_program('int main(void){ FILE *o = fopen("out.txt", "w"); fgets(b, 8, stdin); return 0; }', 'c') == []
    assert check_program('int main(void){ getenv("X"); return 0; }', 'c', {'reject_non_stdin_input': False}) == []
