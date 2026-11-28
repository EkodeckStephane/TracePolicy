# Wazuh and Splunk Attack Data candidate screen

**Screen date:** 2026-11-28  
**Disposition:** technically promising for policy-version replay; benchmark admission NOT VERIFIED.

## Frozen candidate identity

- Wazuh release considered: `v4.14.11` (published 2026-11-25).
- Data source: `Splunk/attack_data`, screened at commit `dee658ae32f156770a85f1b50395158a961738de`.
- Candidate Wazuh changes found between `v4.14.10` and `v4.14.11` include rules `2946/2947` and `88104`. Inspection of the exact XML shows `2946` matches decoded `usermod` messages containing `add '`; `2947` specializes this to `group=sudo`. Rule `88104` matches `Access denied for user` under parent rule `88100`.
- Rule `62149` still matches Windows Defender Event ID 3002 at level 10 in both releases. Its only change is the description substitution from `win.eventdata.feature` to `win.eventdata.featureName`. This is a changed rendering field, not an observed change to the rule's alert decision, so it is unsuitable as the central policy-decision versioning case without a separately justified output-valued decision model.
- The downloaded Defender samples remain isolated under `results/revision/external_candidate_screen/`; neither sample is admitted to the experiment or redistributed by this screen.
- `asr_defender_operational.log`: SHA-256 `cad3567c035dd20c319d3279ea67a8af38340104db4b5311c838ffac82fe6e5f` (9 records: six Event ID 1121 and three Event ID 5007).
- `defender_operational_wineventlog.log`: SHA-256 `e49ea1bdb0d05ec52f1a91164edb5849c110ec4a53cdba41081ac7fc52a63145` (2 records, both Event ID 5007).

## Fit and observed incompatibility

Wazuh is a better runtime candidate than a format-only policy corpus for temporal policy behavior: its official documentation describes the `wazuh-logtest` rule-testing interface, chained rule matching, `frequency`/`timeframe` and grouping options. This gives a possible pinned engine for replaying a fixed sequence against two rule versions.

The two local Attack Data Defender candidates do not match the versioned Wazuh rule change screened here. The small operational sample has two Event ID 5007 records; the larger sample has Event IDs 1121 and 5007. Neither supplies Event ID 3002. A repository search found an Attack Data `usermod` dataset for changing a user's root UID, but that is different from the `usermod` group-add message required by rules 2946/2947; no corresponding sudo-group log or MariaDB authentication-failure dataset was found in the screened corpus. These records therefore cannot substantiate the proposed before/after Wazuh comparison. No Wazuh container run or outcome is claimed.

Attack Data is an attack-oriented curated corpus. Its presence does not establish a benign comparison set, an untouched holdout, or independent generalization. The samples' source-specific provenance and redistribution terms also require verification before inclusion in a public artifact. The runtime and source repositories are separate, so each rule revision must be paired with identical, pre-existing event data and an explicit mapping to the policy semantics used by TracePolicy.

## Admission blockers

1. Find a source trace committed before the Wazuh rule edit and demonstrably relevant to the changed rule, or prospectively collect a new trace without selecting it based on a favorable explanation result.
2. Pin the exact Wazuh engine image/digest, ruleset commit, decoders, configuration, and logtest session semantics; establish a repeatable command-line replay in a clean environment.
3. Freeze how engine outcomes map to TracePolicy decisions and how event/rule interventions map to native Wazuh semantics. Differentially compare the adapter to the engine on the complete candidate domain.
4. Check sample-level provenance, licensing, and any redaction obligations before reuse or publication.
5. Pre-register selection criteria, holdout policy families, metrics, exclusions, and stopping rules before confirmatory evaluation.
6. Include both positive and benign/background traces where the intended claim concerns detection performance; attack-only records can support explanation replay but not false-positive or generalization claims.

## Decision

**Candidate feasibility: PARTIAL PASS. Benchmark admission: NOT VERIFIED.** The engine exposes relevant versioned and temporal-rule mechanisms, and real event streams may be available, but no validated rule-to-trace pair has been established. The current paired pilot remains the only executed policy-version study and does not establish external generalization or operational utility.

**Gate effect:** G8 and G9 remain NOT VERIFIED; G5 remains NOT VERIFIED. Overall decision remains NO-GO.

## Primary sources

- Wazuh rule testing: <https://documentation.wazuh.com/current/user-manual/ruleset/testing.html>
- Wazuh rule syntax: <https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html>
- Wazuh logtest development notes: <https://documentation.wazuh.com/current/development/wazuh-logtest.html>
- Wazuh release comparison: <https://github.com/wazuh/wazuh/compare/v4.14.10...v4.14.11>
- Wazuh rules at v4.14.11: <https://github.com/wazuh/wazuh/blob/v4.14.11/ruleset/rules/0020-syslog_rules.xml>, <https://github.com/wazuh/wazuh/blob/v4.14.11/ruleset/rules/0535-mariadb_rules.xml>, <https://github.com/wazuh/wazuh/blob/v4.14.11/ruleset/rules/0600-win-wdefender_rules.xml>
- Wazuh release tag: <https://github.com/wazuh/wazuh/releases/tag/v4.14.11>
- Splunk Attack Data repository and purpose: <https://github.com/splunk/attack_data>
