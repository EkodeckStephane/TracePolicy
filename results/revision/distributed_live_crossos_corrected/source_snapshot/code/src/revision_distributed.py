"""Trusted-source, event-time coordinator for a bounded distributed laboratory.

This is an ingestion contract, not authenticated logging or clock synchronization.
Watermarks certify source sequence completeness; gaps cannot silently advance time.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Mapping

from trace_policy_engine import Event, PolicyVersion, reference_eval


@dataclass(frozen=True)
class Observation:
    source: str
    source_seq: int
    trace_id: str
    policy_version: int
    event: Event

    def payload(self):
        return dict(source=self.source, source_seq=self.source_seq,
                    trace_id=self.trace_id, policy_version=self.policy_version,
                    event=asdict(self.event))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


class IngestionError(ValueError):
    pass


class JournalCoordinator:
    """Commit only complete source-certified event-time prefixes.

    All expected sources must publish a watermark, and each watermark is held
    until every declared source sequence through its fence has arrived. Policies
    are selected by an immutable event-time schedule. A late record contradicting
    a published completeness fence invalidates the run; no old decision is reused
    as a decision for a missing/late record. Full records are retained for replay.
    """
    def __init__(self, sources, policies: Mapping[int, PolicyVersion], schedule,
                 max_lateness_s=None):
        self.sources = tuple(sorted(sources))
        if not self.sources or len(set(self.sources)) != len(self.sources):
            raise ValueError('sources must be unique and nonempty')
        self.policies = dict(policies)
        if max_lateness_s is not None and max_lateness_s < 0:
            raise ValueError('lateness budget must be nonnegative')
        self.max_lateness_s = max_lateness_s
        self.schedule = tuple(sorted((float(t), int(v)) for t, v in schedule))
        if not self.schedule or any(v not in self.policies for _, v in self.schedule):
            raise ValueError('schedule requires registered immutable policies')
        if len({t for t, _ in self.schedule}) != len(self.schedule):
            raise ValueError('policy cutovers must have distinct times')
        self.records = {}
        self.slots = {}
        self.watermarks = {s: [] for s in self.sources}
        self.closed = set()
        self.committed_ids = set()
        self.prefixes = {}
        self.decisions = []
        self.errors = []
        self.duplicates = 0
        self.cutoff = float('-inf')

    def version_at(self, ts):
        choices = [v for t, v in self.schedule if t <= ts]
        if not choices:
            raise IngestionError('event precedes the first policy version')
        return choices[-1]

    def _fail(self, reason):
        self.errors.append(reason)
        raise IngestionError(reason)

    def record(self, observation: Observation, received_at=None):
        o = observation
        if o.source not in self.sources or o.source_seq < 1 or not o.trace_id:
            self._fail('unknown source, invalid source sequence or missing trace scope')
        if not math.isfinite(o.event.ts) or not o.event.eid:
            self._fail('event identity and finite timestamp are required')
        payload = o.payload()
        if o.event.eid in self.records:
            if canonical(self.records[o.event.eid]) != canonical(payload):
                self._fail('conflicting duplicate event identity')
            self.duplicates += 1
            return 'duplicate'
        if (o.source, o.source_seq) in self.slots:
            self._fail('source sequence reused for a different event')
        if (received_at is not None and self.max_lateness_s is not None
                and received_at - o.event.ts > self.max_lateness_s):
            self._fail('record exceeds the declared lateness budget')
        if o.policy_version != self.version_at(o.event.ts):
            self._fail('record policy version does not match frozen event-time schedule')
        for fence_ts, fence_seq in self.watermarks[o.source]:
            if o.source_seq > fence_seq and o.event.ts <= fence_ts:
                self._fail('record contradicts source watermark completeness')
        if o.event.ts <= self.cutoff:
            self._fail('new event arrived behind the committed watermark')
        self.records[o.event.eid] = payload
        self.slots[(o.source, o.source_seq)] = o.event.eid
        self._flush()
        return 'accepted'

    def watermark(self, source, event_time, through_seq):
        if source not in self.sources or not math.isfinite(event_time) or through_seq < 0:
            self._fail('invalid watermark')
        fences = self.watermarks[source]
        if fences and (event_time < fences[-1][0] or through_seq < fences[-1][1]):
            self._fail('watermark time/sequence must not decrease')
        fences.append((float(event_time), int(through_seq)))
        self._flush()

    def close(self, source):
        if source not in self.sources:
            self._fail('unknown closing source')
        self.closed.add(source)

    def _effective_watermark(self, source):
        valid = [t for t, seq in self.watermarks[source]
                 if all((source, i) in self.slots for i in range(1, seq + 1))]
        return max(valid, default=float('-inf'))

    def _flush(self):
        limit = min(self._effective_watermark(s) for s in self.sources)
        pending = [r for eid, r in self.records.items()
                   if eid not in self.committed_ids and r['event']['ts'] <= limit]
        for record in sorted(pending, key=lambda r: (r['event']['ts'], r['event']['eid'])):
            e = Event(**record['event'])
            prefix = self.prefixes.setdefault(record['trace_id'], [])
            prefix.append(e)
            result = reference_eval(prefix, self.policies[record['policy_version']])
            self.decisions.append(dict(event_id=e.eid, trace_id=record['trace_id'],
                                       policy_version=record['policy_version'],
                                       alert_class=result.alert_class, top=list(result.top)))
            self.committed_ids.add(e.eid)
        self.cutoff = max(self.cutoff, limit)

    def summary(self):
        gaps = {s: [i for i in range(1, max((q for _, q in self.watermarks[s]), default=0) + 1)
                    if (s, i) not in self.slots] for s in self.sources}
        missing_marks = [s for s in self.sources if not self.watermarks[s]]
        pending = len(self.records) - len(self.committed_ids)
        complete = (not self.errors and not any(gaps.values()) and not missing_marks
                    and not pending and self.closed == set(self.sources))
        return dict(status='complete' if complete else 'incomplete',
                    sources=list(self.sources), observed=len(self.records),
                    committed=len(self.committed_ids), pending=pending,
                    duplicate_count=self.duplicates, sequence_gaps=gaps,
                    missing_watermarks=missing_marks, closed_sources=sorted(self.closed),
                    errors=list(self.errors), decisions=list(self.decisions))

    def checkpoint(self, path):
        fingerprints = {str(v): hashlib.sha256(canonical(asdict(p)).encode()).hexdigest()
                        for v, p in self.policies.items()}
        value = dict(schema=1, sources=self.sources, schedule=self.schedule,
                     max_lateness_s=self.max_lateness_s,
                     policies=fingerprints, records=list(self.records.values()),
                     watermarks=self.watermarks, closed=sorted(self.closed),
                     duplicates=self.duplicates, errors=self.errors)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.tmp')
        temporary.write_text(canonical(value), encoding='utf-8')
        temporary.replace(path)

    @classmethod
    def restore(cls, path, policies):
        value = json.loads(Path(path).read_text(encoding='utf-8'))
        coord = cls(value['sources'], policies, value['schedule'],
                    value.get('max_lateness_s'))
        fingerprints = {str(v): hashlib.sha256(canonical(asdict(p)).encode()).hexdigest()
                        for v, p in policies.items()}
        if value['schema'] != 1 or value['policies'] != fingerprints:
            raise IngestionError('checkpoint schema or immutable policies mismatch')
        # Restore factual records first, then completeness fences; replay exactly.
        for r in value['records']:
            coord.record(Observation(r['source'], r['source_seq'], r['trace_id'],
                                     r['policy_version'], Event(**r['event'])))
        for source, marks in value['watermarks'].items():
            for ts, seq in marks:
                coord.watermark(source, ts, seq)
        coord.closed = set(value['closed'])
        coord.duplicates = value['duplicates']
        coord.errors = value['errors']
        return coord
