SUPERSEDED (v0.1.1 copy, kept for provenance only). Contains stale statements, e.g. test counts (54) and approval status. Authoritative: READINESS_PACKET_2026-10-22.md and the documents it pins.

# STATUS — Snowflake demo mission (v2, as of 2026-10-21, UTC)

**v2 update.** The operator kit `szl_ee_operator_kit_20261021.zip` now exists. Stephen can produce ACCOUNT_VERIFIED and DEPLOYMENT_APPROVED evidence himself, on his own machine.
- It is MEASURED in the agent sandbox only, with a fake connector and synthetic data: 54/54 tests pass, and the mutation sweep killed 35 of 36 mutants (1 equivalent).
- A compatibility dry run against the SQL/app track bundle b224275f accepted all 39 `schema.sql` and 4 `reader_grants.sql` statements.
- **No account step has run.** Stephen's 2026-10-21 "green light, do whatever you recommend to finish" is **not** a scoped spend or deployment approval and is not recorded as one. The only accepted approval is the one-line `approval.txt` (AP-H1).

**Overall: NOT operational.** No Snowflake runtime, access, evidence or cost check has passed. This track produced local drafts only.
v5 handoff (artifact 237ba4f2, sha256 991cbecc…bca6) is preserved. Its W28 "Prepare Snowflake wiring" remains `OFFLINE_METADATA_PROPOSAL_37_SYNTHETIC_PASSES`. **Nothing in v5 is marked complete.**

| # | Stage | Status | Evidence / exact blocker | Label |
|---|---|---|---|---|
| 1 | DRAFT_READY | **IN_PROGRESS.** Plan and docs drafts are DONE: SOURCE_VERIFICATION, COVERAGE_LEDGER, DEPLOYMENT_PLAN plus APPROVAL_CHECKLIST, COST_AND_SHUTDOWN, APPLICATION_DRAFT, VIDEO_SCRIPT, STATUS. The SQL schema, app, fixture and tests are owned by another track; their state is UNKNOWN from here. | artifacts of this track | MEASURED (files exist) / UNKNOWN (other track) |
| 2 | LOCAL_TESTED | **IN_PROGRESS** | SQL/app track bundle b224275f states DRAFT_READY / LOCAL_TESTED, with local checks only (REPORTED from its ADR; not re-run here). Operator kit: 54/54 unit tests and a 36-mutant sweep (35 killed, 1 equivalent), using a fake connector and synthetic data (MEASURED 2026-10-21). Local tests do not establish live access or behaviour. | REPORTED / MEASURED |
| 3 | ACCOUNT_VERIFIED | **BLOCKED** (path ready) | No Snowflake credential in the agent environment. The account is known only from a historical observation and may be suspended (UNKNOWN). **Next:** Stephen runs `sf_verify_account_readonly.py` (OPERATOR_RUNBOOK step 1) and brings back the sanitized JSON plus the trial balance, expiry and suspended status as text. | UNKNOWN |
| 4 | DEPLOYMENT_APPROVED | **BLOCKED** (path ready) | Snowflake spending authorization NOT YET SPECIFIED. APPROVAL_CHECKLIST groups A–H are unanswered, and no `approval.txt` exists. **Next:** checklist answers, a MANIFEST.json pinning the reviewed bundle, an approval line, a reviewed dry run, then the manual B1 block (runbook steps 2–4). | REPORTED (mission §1) |
| 5 | PRIVATE_DEMO_VERIFIED | **BLOCKED** | Depends on stages 2–4; no deployment exists. When unblocked: `sf_deploy_pilot.py --execute`, a per-session window, the SQL/app track's integration checks, then `sf_shutdown_verify.py` (runbook steps 5–7). | — |
| 6 | VIDEO_REVIEWED | **BLOCKED** (VIDEO_NOT_READY) | no recording; the historical mp4 is EXCLUDED | MEASURED (blob exists, unreviewed) |
| 7 | HOSTING_APPROVED | **BLOCKED** | no final file; no hosting approval | — |
| 8 | VIDEO_ACCESS_VERIFIED | **BLOCKED** | no hosted URL | — |
| 9 | APPLICATION_REVIEW_READY | **BLOCKED** | Q16 and Q24 pending. Legal name, jurisdiction and form units are missing. The 2027 rules are unpublished (UNKNOWN). | REPORTED / UNKNOWN |
| 10 | SUBMITTED_WITH_CONFIRMED_RECEIPT | NOT_RUN | not authorized; agents never submit | — |

Other blocked or limited operations this session (MEASURED, 2026-10-21):
- www.snowflake.com (challenge page and FAQ) and developers.cloudflare.com/dns returned **HTTP 403, Cloudflare error 1010**. The User-Agent was not spoofed.
- GitHub anonymous REST returned **403 rate limit** at 12:07:09Z (reset 12:24:45Z). The repo count (129) therefore comes from the HTML page and is provisional. The video's last-modifying commit is UNKNOWN.
- Cloudflare account and zone configuration: not accessed, because there is no authorized access. Only public DNS was read.

## What Stephen must supply next (grouped; one reply covers all)

**1. Facts, no spend (AP-A1, AP-A2).** Run `sf_verify_account_readonly.py` (runbook step 1), and check these in your own Snowsight session and report them:
- edition and region;
- trial or paid status, balance and expiry;
- whether a card is on file and whether the account is suspended;
- the ACCOUNTADMIN user;
- existing warehouses, tasks and compute pools, with their states.

**2. Spending (AP-B1–B4).**
- Credit cap. Proposed: 10 credits.
- USD ceiling. The REPORTED secondary range for 10 credits is USD 30–46.50; the actual rate is UNKNOWN.
- Session window. Proposed: 3 sessions of ≤ 3 h within 14 days.
- Trial-only, yes or no. Proposed: trial only, no upgrade.

**3. Admin and security (AP-C1–C5, AP-D1–D3).**
- Role, warehouse, database and managed-access schema names and grants, as proposed.
- ACCOUNTADMIN limited to the resource monitor.
- No integrations, secrets, service users or embedding.
- Defer ALLOWED_INTERFACES and PREVENT_UNLOAD_TO_INTERNAL_STAGES.

**4. Data and app (AP-E1, E2, F1–F3).**
- A MANIFEST.json pinning schema.sql, reader_grants.sql, streamlit_app.py and evidence_core.py from the reviewed bundle, plus the fixture digest.
- Retention choice.
- Sleep timer value.
- Viewer audience. Proposed: you only.

**5. Approval line (AP-H1).** Write the one line from APPROVAL_TEMPLATE.txt yourself. It is machine-checked: N ≤ 10, a future UTC date within 31 days, and your account locator.

**6. Rollback (AP-G1, G2).**
- Pre-approve suspend and revoke as safety actions.
- Every DROP, TRUNCATE or DELETE stays separately approved.

**7. Application facts (APPLICATION_DRAFT §Remaining).**
- Legal name, jurisdiction, address, good standing.
- Whether the USD 80,000 was an equity sale.
- Snowflake program history.
- Who signs the rules.
- A working contact email (a-11-oy.com and a11oy.net publish SPF -all and DMARC reject).

**8. Later, separate approvals.**
- Video content review.
- Hosting destination and audience.
- Final application text and rules acceptance.
- Submission.
