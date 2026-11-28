# Continuation addendum — Wazuh external-candidate audit

**Date:** 2026-11-28  
**Repository commit:** `4733b71799bb45be78ec64814a52498cf43d91bd`  
**CI:** run `46147138346`, in progress at time of recording.  
**Decision:** NO-GO remains.

## Evidence added

The exact Wazuh v4.14.10-to-v4.14.11 ruleset diff was examined. The release adds rules 2946/2947 for decoded `usermod` group-add messages (rule 2947 targets `sudo`) and rule 88104 for MariaDB authentication failures. Windows Defender rule 62149 continues to match Event ID 3002 at level 10 in both versions; the changed field only affects the interpolated description. That is not a changed alert decision and is excluded as the central versioned-decision case.

Attack Data search found a Linux `usermod` sample concerning a root UID change, which does not match the `usermod` group-add condition. The two screened Defender logs contain Event IDs 1121 and 5007, not 3002. No MariaDB failure trace or matching sudo-group addition trace was located in the screened repository. The sample hashes and local event counts are recorded in `WAZUH_ATTACK_DATA_CANDIDATE_SCREEN_2026-11-28.md`; raw samples remain uncommitted and unadmitted.

## Updated gate interpretation

- **G8 — NOT VERIFIED:** there is still no untouched independent confirmatory holdout. The external source screen did not yield a compatible rule/trace pair.
- **G9 — NOT VERIFIED:** a practical version-change explanation benchmark has not been established. The candidate Defender rule changes presentation only, while the behavior-changing Wazuh additions lack a demonstrated compatible pre-existing trace.
- **G5 — NOT VERIFIED:** no fair native-versus-certified comparison has been run.

No engine replay, detection-performance estimate, operational-utility result, or generalization claim is made. The structured gate file now points to the Wazuh screen and the latest public commit; its CI field records the observed in-progress state rather than assuming success.

## Next evidence-producing action

Continue screening policy-version histories and telemetry for a pre-existing trace that actually exercises a behavior-changing rule edit. For any candidate, first validate exact rule/trace compatibility and licensing, then freeze the rule versions, runtime, input stream, intervention mapping, and holdout protocol before running paired replay. If no compatible public pair exists, obtain prospectively collected traces under a frozen policy-change protocol; do not treat generated rule fixtures as external validation.
