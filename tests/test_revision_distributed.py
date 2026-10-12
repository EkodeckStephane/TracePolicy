import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from trace_policy_engine import Event, Rule, Selector, Guard, PolicyVersion, ALLOW, DENY, reference_eval
from revision_distributed import JournalCoordinator, Observation, IngestionError


def policies():
    allow = Rule('allow', 0, ALLOW, Selector())
    deny = Rule('chain', 10, DENY, Selector('connect'),
                Guard(seq_actions=('read', 'exec', 'connect'), seq_horizon=3))
    return {1: PolicyVersion('lab', 1, (allow,)),
            2: PolicyVersion('lab', 2, (allow, deny))}


def observations():
    return [Observation('A', 1, 'joint', 1, Event('r', 1, 'read', 'lab', 'user')),
            Observation('B', 1, 'joint', 2, Event('x', 2, 'exec', 'lab', 'user')),
            Observation('A', 2, 'joint', 2, Event('c', 3, 'connect', 'lab', 'user'))]


def complete(coord):
    coord.watermark('A', 4, 2)
    coord.watermark('B', 4, 1)
    coord.close('A'); coord.close('B')


def test_reordering_and_delayed_duplicate_match_complete_reference():
    p = policies(); coord = JournalCoordinator(['A', 'B'], p, [(0, 1), (1.5, 2)])
    r, x, c = observations()
    coord.record(c); coord.record(x)
    complete(coord)
    assert coord.summary()['status'] == 'incomplete'
    assert coord.decisions == []  # source sequence gap blocks claimed watermark
    coord.record(r)
    assert coord.summary()['status'] == 'complete'
    assert coord.record(r) == 'duplicate'
    prefix = []
    expected = []
    for o in [r, x, c]:
        prefix.append(o.event)
        expected.append(reference_eval(prefix, p[o.policy_version]).alert_class)
    assert [d['alert_class'] for d in coord.decisions] == expected
    assert expected == ['NoAlert', 'NoAlert', 'Violation']


def test_missing_prerequisite_stays_incomplete_not_falsely_benign():
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)])
    _, x, c = observations()
    coord.record(x); coord.record(c); complete(coord)
    assert coord.summary()['sequence_gaps']['A'] == [1]
    assert coord.summary()['status'] == 'incomplete'
    assert coord.decisions == []


def test_conflicting_duplicate_invalidates_run():
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)])
    r, _, _ = observations(); coord.record(r)
    changed = Observation('A', 1, 'joint', 1, Event('r', 1, 'write', 'lab', 'user'))
    with pytest.raises(IngestionError, match='conflicting duplicate'):
        coord.record(changed)
    assert coord.summary()['errors']


def test_late_event_contradicting_watermark_is_not_silently_appended():
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)])
    r, x, _ = observations(); coord.record(r); coord.record(x)
    coord.watermark('A', 2.5, 1); coord.watermark('B', 2.5, 1)
    late = Observation('A', 2, 'joint', 2, Event('late', 2.2, 'connect', 'lab', 'user'))
    with pytest.raises(IngestionError, match='contradicts source watermark'):
        coord.record(late)
    assert len(coord.decisions) == 2


def test_policy_binding_and_trace_scope_are_enforced():
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)])
    r, x, c = observations()
    with pytest.raises(IngestionError, match='policy version'):
        coord.record(Observation('A', 2, 'joint', 1, c.event))
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)])
    coord.record(r); coord.record(x)
    coord.record(Observation('A', 2, 'different_session', 2, c.event))
    complete(coord)
    assert coord.decisions[-1]['alert_class'] == 'NoAlert'


def test_declared_lateness_budget_fails_closed():
    coord = JournalCoordinator(['A', 'B'], policies(), [(0, 1), (1.5, 2)], .5)
    r, _, _ = observations()
    with pytest.raises(IngestionError, match='lateness budget'):
        coord.record(r, received_at=1.6)
    assert coord.summary()['status'] == 'incomplete'
    assert coord.summary()['observed'] == 0


def test_checkpoint_replay_and_idempotent_delivery(tmp_path):
    p = policies(); coord = JournalCoordinator(['A', 'B'], p, [(0, 1), (1.5, 2)])
    r, x, c = observations()
    coord.record(c); coord.record(x)
    coord.watermark('A', 4, 2); coord.watermark('B', 4, 1)
    checkpoint = tmp_path / 'checkpoint.json'; coord.checkpoint(checkpoint)
    restored = JournalCoordinator.restore(checkpoint, p)
    restored.record(r); complete(restored)
    expected = restored.summary()
    restored.checkpoint(checkpoint)
    replayed = JournalCoordinator.restore(checkpoint, p)
    assert replayed.summary() == expected
    replayed.record(c)
    assert replayed.decisions == expected['decisions']
    altered = policies(); altered[2] = PolicyVersion('lab', 2, (Rule('other', 0, ALLOW, Selector()),))
    with pytest.raises(IngestionError, match='immutable policies'):
        JournalCoordinator.restore(checkpoint, altered)
