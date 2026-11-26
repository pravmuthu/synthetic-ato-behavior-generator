# V3.2 Research Methodology, Provenance, and Validation Notes

## Scope and evidence

This document describes synthetic generative assumptions, not observed account takeover behavior. The aim is to test the methodological feasibility of comparing authentication-only versus time-bounded post-login information. The simulator is best described as a **reproducible controlled testbed**, *not* a realistic, externally validated fraud dataset. All rates, geography, step frequencies, delays and risk relationships are synthetic choices.

## Unit of evaluation

A successful authenticated session is one observation. A positive is **unauthorized actor control**; the attack objective might be completed, blocked or abandoned. An attacker can be quiet and perform no objective action. The `episode_ground_truth.csv` stores attack objective and timing separately to avoid contaminating the true actor label with the outcome.

## Population

Accounts belong to configurable `marketplace`, `business_banking`, and `saas` application profiles. There can be multiple users per account with administrator/manager/staff roles. Simulated history includes recurring weekday usage, account activity cohorts, user-specific preferred journey patterns, variable device familiarity, VPN/mobile/office/home networks and shared legitimate agency fingerprints. Global pseudo-geography includes multiple countries and cities. Some attackers use familiar devices/IPs, while some legitimate sessions use unfamiliar ones. Observed session login history, not string suffixes, determines device familiarity.

## Simulation and overlap controls

A session may consist of independent ordinary journeys or special actor-known episodes. The four objectives are expressed in a common event vocabulary with platform-specific raw labels. Routine sessions sometimes include sensitive actions; episode sessions can contain ordinary browsing and the same kinds of benign sensitive operations. Attack stealth and benign complexity are separate inputs, and the observed training labels can mask positives while true ground truth remains stable.

The validator checks referential integrity, temporal order, one successful authentication per session, time-consistent device/IP familiarity, the four objectives and their variants, role constraints for sensitive operations, absent explicit label columns, and category overlap. These checks are **necessary, not sufficient** for statistical realism or detector fairness.

## Threats to validity

1. **Construct validity:** labels represent injected actor identity; simulator cannot prove real takeover intent. It assumes unauthorized control is known by construction.
2. **Internal validity:** behavior is produced from programmed journey templates and user preference distributions; ML can learn these artifacts.
3. **External validity:** no telemetry-informed calibration of genuine login, work, consumer, enterprise, or adversarial activity. Profile diversity does not prove generalization to genuine platforms.
4. **Temporal validity:** user access roles remain static; synthetic policy dynamics, abandoned MFA flows and account lifecycle changes are simplified.
5. **Statistical validity:** sessions from users/accounts are correlated; the number of positive independent accounts—not the number of clickstream events—is the more relevant replication count. Bootstrapping by event row is invalid.
6. **Prevalence shift:** the 360-case dataset is deliberately enriched; reported precision cannot be interpreted as real-market precision without base-rate assumptions and deployment validation.
7. **Historical leakage:** an engineer could easily create leakage by aggregating all events or looking up account future activity. Features must be computed strictly with timestamps earlier than the checkpoint.
8. **Benign-lookalike matching:** actor groups are deliberately constructed to share high-risk patterns. Such matched cases test a specific stress condition, not representative benign prevalence.
9. **Identifier shortcut risk:** IDs are opaque, but any simulation may have subtle mechanical artifacts. Drop IDs as raw ML features and run exploratory univariate and tree-stump shortcut audits on each generated world.

## Suggested publication-quality experiment controls

Use independent seeds for train/validation/test worlds; vary `--stealth` and `--benign-complexity` separately; compare multiple prevalence configurations; hold out some path templates when possible. Report confidence intervals from independent simulation worlds or clusters, not individual clickstream events. Consider an external login dataset or independently implemented simulator for robustness checks. No deployment generalizability claim is supported without real-data evaluation.

## Data visibility

- **T0:** successful login and preceding authentication/session history only.
- **T+30:** T0 + observed clickstream events within 30 seconds of login.
- **T+60:** T0 + observed clickstream events within 60 seconds.
- **T+300:** T0 + observed clickstream events within 300 seconds.
- **Sensitive-action ablation:** exclude writes/exports from the observed features; use other navigation/time features only.
- **Early prevention analysis:** count detection as pre-action only if the model raises an alert before `first_harmful_action_utc`.

No learned model or predictive performance is provided in this kit. Validation confirms generation integrity and a selection of obvious shortcut checks only.
