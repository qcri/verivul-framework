from slicer import slice_function

GUARD = """static int process(struct ctx *c, const uint8_t *buf, size_t len, size_t offset) {
    int total = 0;
    log_debug("enter");
    if (offset > MAX_OFF) {
        return -1;
    }
    size_t idx = offset + len;
    for (int i = 0; i < 4; i++) {
        c->stats[i] += 1;
    }
    if (c->mode == 2) {
        total = buf[idx];
    }
    return total;
}
"""
ELSE = """static void proc(uint32_t size_left, int count, int ent) {
	while ( size_left ) {
		uint32_t size_required;
		size_required = 4*count;
		for ( int i=0; i<count; i++ ) {
			if ( ent ) {
				size_required += 4;
			} else {
				size_required += 8;
			}
		}
		size_left -= size_required;
	}
}
"""


def balanced(s):
    return s.count("{") == s.count("}")


def test_inserted_guard_points_at_the_guarded_sink():
    fixed = GUARD.replace("    size_t idx = offset + len;\n",
                          "    size_t idx = offset + len;\n    if (idx >= c->cap) return -1;\n")
    r = slice_function(GUARD, fixed_src=fixed, language="c")
    assert r.criterion_source == "diff"
    assert "total = buf[idx];" in r.sliced_code
    assert "log_debug" not in r.sliced_code
    assert balanced(r.sliced_code)


def test_control_statement_contributes_header_only():
    fixed = GUARD.replace("        total = buf[idx];", "        total = idx < 64 ? buf[idx] : 0;")
    r = slice_function(GUARD, fixed_src=fixed, language="c")
    assert "c->stats[i] += 1;" not in r.sliced_code
    assert r.num_stmts_after < r.num_stmts_before
    assert balanced(r.sliced_code)


def test_else_clause_rows_are_closed():
    fixed = ELSE.replace("\t\tsize_left -= size_required;",
                         "\t\tif (size_required > size_left) return;\n\t\tsize_left -= size_required;")
    r = slice_function(ELSE, fixed_src=fixed, language="c")
    assert balanced(r.sliced_code)
    assert "size_left -= size_required;" in r.sliced_code


def test_cwe_fallback_is_sink_based():
    r = slice_function(GUARD, cwe="CWE-787", language="c")
    assert r.criterion_source == "cwe"
    assert r.num_stmts_after < r.num_stmts_before
    assert balanced(r.sliced_code)
