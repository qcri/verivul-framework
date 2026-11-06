"""The VULNERABLE -> sanitizer -> LLM proof of concept -> replay -> regenerate flow of the
ESBMC agent, with the database, the queue and the sanitizer replaced by fakes."""
import base64
import logging
from types import SimpleNamespace

import pytest

from src.agents.esbmc_agent import ESBMCAgent
from src.db.models import Label, Status
from src.utils.queue import Outcome


class FakeDB:
    def __init__(self, *snippets):
        self.rows = {s.uuid: s for s in snippets}
        self.deleted = []

    def get_snippet(self, uuid):
        return self.rows.get(uuid)

    def update_snippet(self, uuid, metadata):
        for k, v in metadata.items():
            setattr(self.rows[uuid], k, v)
        return True

    def delete_snippet(self, uuid):
        self.deleted.append(uuid)
        self.rows.pop(uuid, None)

    def increment_pair_attempts(self, uuid):
        return 0


class FakeProducer:
    def __init__(self):
        self.sent = []

    def publish_message(self, queue, msg):
        self.sent.append((queue, msg))
        return True


def snippet(uuid, label='VULNERABLE', parent=None, **kw):
    base = dict(uuid=uuid, seed_uuid='seed', generation_model='m', language='c', code='int main(void){return 0;}',
                label=label, parent_uuid=parent, esbmc_log='', verification_meta={'violated_properties': [
                    {'description': 'dereference failure: array bounds violated', 'line': 7, 'in_program': True}]},
                reproduced=None, poc_input=None, reproduce_attempts=0, cwes=[], project='', commit_message='',
                install_command='', metrics={}, slice_code='')
    base.update(kw)
    return SimpleNamespace(**base)


FINDING = {'kind': 'heap-buffer-overflow', 'function': 'f', 'line': 7, 'input_b64': base64.b64encode(b'x').decode(),
           'report': '==1==ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 4', 'input_as_path': False}


def agent(db, finds):
    a = ESBMCAgent.__new__(ESBMCAgent)
    a.db, a.producer, a.log = db, FakeProducer(), logging.getLogger('test')
    calls = []

    def fake_run(code, language, label, esbmc_log, vmeta, seeds=None, seed=1, runs=None):
        calls.append({'label': label, 'seeds': seeds, 'runs': runs})
        f = finds(len(calls), seeds) if callable(finds) else finds
        return {'result': ('confirmed_exact' if label == 'VULNERABLE' else 'counterexample_found') if f
                else ('not_reproduced' if label == 'VULNERABLE' else 'no_crash_found'), 'finding': f}
    a._run_sanitizer = fake_run
    a.advanced = []
    a._advance = lambda s, label: a.advanced.append(s.uuid)
    a.calls = calls
    return a


def tasks(a):
    return [m.get('task_type') or m.get('task') for _, m in a.producer.sent]


def test_reproduced_label_stores_crash_and_advances():
    db = FakeDB(snippet('v'))
    a = agent(db, FINDING)
    conf = a._confirm_and_store(db.rows['v'], Label.VULNERABLE, Status.VERIFICATION_SUCCESS, '', {})
    assert not a._needs_poc(conf, Label.VULNERABLE)
    row = db.rows['v']
    assert row.reproduced == 'REPRODUCED' and row.poc_input == FINDING['input_b64']
    assert row.sanitizer_cwes == ['CWE-122', 'CWE-787'] and 'heap-buffer-overflow' in row.sanitizer_log


def test_unreproduced_label_asks_for_poc_then_replays_and_advances():
    db = FakeDB(snippet('v'))
    a = agent(db, lambda n, seeds: FINDING if seeds else None)
    conf = a._confirm_and_store(db.rows['v'], Label.VULNERABLE, Status.VERIFICATION_SUCCESS, '', {})
    assert a._needs_poc(conf, Label.VULNERABLE)
    a._request_poc(db.rows['v'], 1, [])
    assert db.rows['v'].reproduced == 'PENDING' and tasks(a) == ['reproduce_poc']
    out = a._process_one({'uuid': 'v', 'task': 'replay_poc', 'round': 1, 'tried': [],
                          'seeds': [base64.b64encode(b'MAGIC').decode()]})
    assert out == Outcome.ACK and a.calls[-1]['seeds'] == [b'MAGIC']
    assert db.rows['v'].reproduced == 'REPRODUCED' and a.advanced == ['v']


def test_exhausted_rounds_mark_not_reproduced_and_regenerate_with_feedback(monkeypatch):
    seed = snippet('seed', label='UNKNOWN', code='seed code')
    db = FakeDB(snippet('v'), seed)
    a = agent(db, None)
    a._process_one({'uuid': 'v', 'task': 'replay_poc', 'round': 1, 'tried': [], 'seeds': []})
    assert tasks(a) == ['reproduce_poc']                       # round 2 requested
    a._process_one({'uuid': 'v', 'task': 'replay_poc', 'round': 2, 'tried': [], 'seeds': []})
    assert db.rows['v'].reproduced == 'NOT_REPRODUCED' and a.advanced == []
    _, gen = a.producer.sent[-1]
    assert gen['task_type'] == 'generate' and gen['seed_uuid'] == 'seed' and gen['reproduce_attempts'] == 1
    assert 'stdin' in gen['feedback'] and 'array bounds' in gen['feedback']


def test_regeneration_stops_at_the_cap():
    db = FakeDB(snippet('v', reproduce_attempts=2), snippet('seed', label='UNKNOWN'))
    a = agent(db, None)
    a._process_one({'uuid': 'v', 'task': 'replay_poc', 'round': 2, 'tried': [], 'seeds': []})
    assert db.rows['v'].reproduced == 'NOT_REPRODUCED' and tasks(a) == []


def test_unreproducible_injection_is_removed_and_repaired():
    db = FakeDB(snippet('p', label='SAFE'), snippet('child', parent='p'))
    a = agent(db, None)
    a._process_one({'uuid': 'child', 'task': 'replay_poc', 'round': 2, 'tried': [], 'seeds': []})
    assert db.deleted == ['child'] and tasks(a) == ['inject_vulnerability']


@pytest.mark.parametrize('crashes,rejected', [(True, True), (False, False)])
def test_fix_must_remove_the_parents_crash(crashes, rejected):
    parent = snippet('p', reproduced='REPRODUCED', poc_input=base64.b64encode(b'boom').decode())
    child = snippet('fix', label='SAFE', parent='p')
    a = agent(FakeDB(parent, child), FINDING if crashes else None)
    reason = a._parent_crash_persists(parent, child, '', {})
    assert bool(reason) is rejected
    assert a.calls[-1] == {'label': 'SAFE', 'seeds': [b'boom'], 'runs': 1}


def test_poc_chunks_are_decoded_and_bad_candidates_skipped():
    from src.utils.poc import parse_candidates
    resp = ('<think>x</think><poc>{"candidates": ['
            '[{"hex": "47424b4d"}, {"u32le": 1}, {"u16be": 65537}, {"text": "A\\n"}, {"repeat": {"hex": "00", "count": 3}}],'
            '[{"bogus": 1}], [{"i32le": -1}]]}</poc>')
    assert parse_candidates(resp) == [b'GBKM\x01\x00\x00\x00\x00\x01A\n\x00\x00\x00', b'\xff\xff\xff\xff']
    assert parse_candidates('<poc>{"candidates": [[{"repeat": {"hex": "41", "count": 99999999}}]]}</poc>') == []
    assert parse_candidates('no json here') == []


def test_llm_poc_task_publishes_a_replay():
    import asyncio
    from src.agents.llm_agent import LLMAgent
    db = FakeDB(snippet('v'))
    llm = LLMAgent.__new__(LLMAgent)
    llm.db, llm.producer, llm.log, llm.poc_user_prompt = db, FakeProducer(), logging.getLogger('t'), 'write input'

    async def answer(messages):
        assert 'write input' in messages[0]['content'] and 'tried-before' in messages[0]['content']
        msg = SimpleNamespace(content='<poc>{"candidates": [[{"text": "OPEN 0 1 5\\n"}]]}</poc>')
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])
    llm._call_llm_api = answer
    asyncio.run(llm._handle_reproduce_poc({'uuid': 'v', 'round': 2, 'tried': ['tried-before']}))
    queue, msg = llm.producer.sent[0]
    assert queue.startswith('esbmc') and msg['task'] == 'replay_poc' and msg['round'] == 2
    assert [base64.b64decode(s) for s in msg['seeds']] == [b'OPEN 0 1 5\n'] and len(msg['tried']) == 2


def test_rejected_fix_feeds_the_verifier_report_into_the_retry():
    parent = snippet('p', code='int main(void){\n  return 0;\n}\n')
    a = agent(FakeDB(parent), None)
    child_log = ("[Counterexample]\nViolated property:\n  file /work/source.c line 2 column 3 function main\n"
                 "  dereference failure: forgotten memory: dynamic_1_array\n\nVERIFICATION FAILED\n")
    a._retry_pairing(parent, 'derived label VULNERABLE equals parent label', 'int main(void){\n  return 1;\n}\n', child_log, {})
    _, msg = a.producer.sent[-1]
    assert msg['task_type'] == 'vulnerability_fix' and msg['previous_code'].startswith('int main')
    assert 'forgotten memory' in msg['feedback'] and 'line 2' in msg['feedback']
    a._retry_pairing(parent, 'derived verdict is UNKNOWN', 'int main(void){}', 'ERROR: Timed out', {})
    assert 'time budget' in a.producer.sent[-1][1]['feedback']


def test_fix_prompt_carries_the_crash_and_the_previous_attempt():
    from src.agents.llm_agent import LLMAgent
    s = snippet('v', reproduced='REPRODUCED', sanitizer_log='ERROR: AddressSanitizer: heap-buffer-overflow',
                poc_input=base64.b64encode(b'MAGIC\x01').decode())
    crash = LLMAgent._crash_section(s)
    assert 'heap-buffer-overflow' in crash and 'MAGIC' in crash
    assert LLMAgent._crash_section(snippet('u')) == ''
    retry = LLMAgent._attempt_section({'feedback': 'rejected: X', 'previous_code': 'int f;'})
    assert 'rejected: X' in retry and 'int f;' in retry and LLMAgent._attempt_section({}) == ''


def test_fixes_go_to_the_configured_fixer(monkeypatch):
    from config.settings import settings
    from src.utils.queue import counterpart_queue, make_queue_name
    monkeypatch.setattr(settings, 'pairing', {'fix_model': 'gemma-4-31b-it'})
    monkeypatch.setattr(settings, 'models', {'gemma-4-31b-it': {'enabled': True}, 'qwen3.8-27b': {'enabled': True}})
    assert counterpart_queue('vulnerability_fix', 'qwen3.8-27b') == make_queue_name('llm', 'gemma-4-31b-it')
    assert counterpart_queue('inject_vulnerability', 'qwen3.8-27b') == make_queue_name('llm', 'qwen3.8-27b')
    monkeypatch.setattr(settings, 'pairing', {})
    assert counterpart_queue('vulnerability_fix', 'qwen3.8-27b') == make_queue_name('llm', 'qwen3.8-27b')


def test_fix_that_still_crashes_is_rejected_before_esbmc():
    parent = snippet('p', reproduced='REPRODUCED', poc_input=base64.b64encode(b'boom').decode())
    child = snippet('fix', label='UNKNOWN', parent='p', verified_code_hash=None, status='COMPILATION_SUCCESS')
    db = FakeDB(parent, child)
    a = agent(db, FINDING)
    a.verify_code = lambda **kw: pytest.fail('ESBMC must not run on a fix that still crashes')
    assert a._process_one({'uuid': 'fix'}) == Outcome.ACK
    assert db.deleted == ['fix']
    _, msg = a.producer.sent[-1]
    assert msg['task_type'] == 'vulnerability_fix' and 'still crashes' in msg['feedback'] and msg['previous_code']
