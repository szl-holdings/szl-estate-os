SUPERSEDED (v0.1.1 copy, kept for provenance only). Contains stale statements, e.g. test counts (54) and approval status. Authoritative: READINESS_PACKET_2026-10-22.md and the documents it pins.

# COST_AND_SHUTDOWN — Snowflake private pilot (v2)

**v2, 2026-10-21:** warehouse and monitor names are aligned to the SQL/app track (`SZL_EE_WH`, `SZL_EE_RM`). Section 6 can now be run as `sf_shutdown_verify.py` from the operator kit; it is read-only and prints PASS/FAIL/UNKNOWN. Figures are unchanged.

Status: **DRAFT — PROPOSAL ONLY. NOT APPROVED. NOT RUN.** Prepared 2026-10-21 (UTC).
Every figure below is an *estimate under stated assumptions*. **Snowflake spending authorization: NOT YET SPECIFIED** (mission §1).
The prior "2000 max" / 50-hour authorization covered a VM training job. It is **not** reassigned here, and its currency is not assumed.

## 1. Rates and billing rules (from docs fetched 2026-10-21; REPORTED from docs, untested in the account)

| Item | Documentation says | Source | Label |
|---|---|---|---|
| X-Small warehouse | 1 credit per full hour per cluster; billed per second | warehouses-considerations | MEASURED fetch / REPORTED doc |
| Minimum per start | 60 s charged each time compute is provisioned; per-second after that | warehouses-considerations | same |
| AUTO_SUSPEND | Default 600 s. The doc warns that 1–2 min settings can cause frequent suspend/resume cycles, each charged the 60 s minimum. Suspension is checked on a 30 s poll. | warehouses-considerations; CREATE WAREHOUSE | same |
| Streamlit warehouse runtime | Each visit resumes the code warehouse. The WebSocket keeps it active until about 15 min after the viewer's last activity (mouse movement counts). | streamlit/object-management/billing | same |
| Streamlit container runtime | Long-running compute-pool billing until 3 days of inactivity. **Not used.** | same | same |
| Cloud services | Billed only above 10% of daily warehouse usage. **Resource monitors count all cloud-services usage toward the quota**, even when it is not billed. | cost-understanding-compute; resource-monitors | same |
| Resource monitors | Warehouses only. Not serverless or AI. **Not intended for precise or hourly limits.** Charges can continue after a suspend (cloud services). Only ACCOUNTADMIN can create one. | resource-monitors | same |
| Budgets | Monthly. Refresh latency up to 6.5 h (1 h for low-latency). The budget itself runs billed serverless tasks. | budgets; budgets/cost | same |
| Trial | 30 days from sign-up, or until the free balance is used up. Compute and storage both draw it down. When the trial ends the account is suspended. Reactivation needs a card plus an upgrade to paid. | admin-trial-account | same |
| **Price per credit** | Not published in the fetched docs. Secondary guides report about **USD 3.00** for Enterprise in AWS US East on demand, and **USD 3.00–4.65** for Enterprise across regions. **The ca-central-1 rate, the trial balance conversion and the currency for this account are UNKNOWN.** | web search 2026-10-21 (secondary pricing guides) | REPORTED (secondary) / **UNKNOWN** for this account |
| Storage | Synthetic fixture is KB-scale. Permanent tables carry Time Travel (1 day proposed) plus 7-day Fail-safe. | — | estimate; magnitude negligible but non-zero |

## 2. Credit estimate for build + test + recording (assumptions explicit)

Assumptions:
1. One XS warehouse, single cluster, used for both app code and queries.
2. AUTO_SUSPEND = 60 s.
3. AUTO_RESUME is enabled only inside approved windows.
4. Each viewer session keeps the warehouse up for the full ~15 min WebSocket tail; no custom sleep timer is relied on.
5. No Cortex, serverless, tasks, compute pools or budgets objects.

| Phase | Assumption | XS warehouse hours (= credits) |
|---|---|---|
| Admin DDL/grants (B1–B10) | Mostly cloud-services metadata. Assume the warehouse is resumed briefly for checks. | 0.25 |
| Fixture load + verification (B11) | Duplicate-safe batch, reruns and row-count queries: about 30 min active | 0.50 |
| Integration checks (G) | About 11 mission §8 checks: about 60 min active | 1.00 |
| App dev/test sessions (warehouse runtime) | 3 sessions × (20 min use + 15 min WebSocket tail) | 1.75 |
| Recording takes | 2 takes × (10 min setup/rehearsal + 5 min take + 15 min tail) | 1.00 |
| Shutdown + usage reconciliation queries | ACCOUNT_USAGE queries now and again after 3–6 h latency: 2 × 15 min | 0.50 |
| 60-second minimum on resumes | About 25 resumes × up to 1 extra min each | 0.42 |
| **Warehouse subtotal** | | **5.42** |
| Cloud-services usage counted by the monitor | assumed ≤ 0.5 credit. Billed amount is likely 0 under the 10% adjustment, but the monitor counts it anyway. | 0.50 |
| **Point estimate** | | **5.92 credits** |
| × 1.5 buffer | billing lag (metering latency up to 3–6 h), browser tabs left open, repeated takes | **8.88 credits** |

## 3. Maximum requested budget (PROPOSAL for Stephen; not assumed)
- **Cap: 10 credits** for the whole pilot. This is the resource monitor `CREDIT_QUOTA`, with `FREQUENCY = NEVER` and an END_TIMESTAMP at the pilot end.
  - Triggers: notify at 50% and 75%, SUSPEND at 90%, SUSPEND_IMMEDIATE at 100%.
  - The cap is above the buffered estimate of 8.88, so the 90% suspend acts as a backstop rather than cutting off a planned session.
- **USD-equivalent at the REPORTED secondary range:** 10 × USD 3.00–4.65 = **USD 30.00–46.50**.
  - Not a quote. The actual rate for this account is UNKNOWN.
  - Stephen should also set a USD ceiling (AP-B2). Whichever limit is reached first wins.
- **Duration:** up to 3 approved sessions of ≤ 3 h each, within 14 calendar days (proposal; AP-B3).
- **Trial-credit vs paid:**
  - If the trial is still active, consumption reduces the trial balance. The historical balance was about USD 400 (REPORTED), and the cap is about 7.5–11.6% of that.
  - If the trial has expired, the account is suspended. Proceeding would then require adding a card and upgrading to **paid**. That is **out of scope** without a new, explicit spending approval (AP-B4 proposed: no).
  - Adding a card also enables AI features on trials (docs). That is another reason not to do it for pilot 1.
- **Not covered by the monitor:** serverless, AI, budgets' own tasks, storage, and any pre-existing warehouses not assigned to `SZL_EE_RM`. Check that existing warehouses stay suspended (P2).

## 4. Resource-monitor caveats to state to reviewers
- It is **not a precise-dollar hard cap**.
  - Running statements finish after SUSPEND.
  - SUSPEND_IMMEDIATE cancels statements, but overshoot within a statement is possible. STATEMENT_TIMEOUT_IN_SECONDS = 120 bounds this.
  - Cloud-services charges can continue after suspension.
- Notifications are off by default and must be enabled. Non-admin users only receive email for warehouse monitors.
- Once suspended by the monitor, the warehouse cannot resume until one of these happens: the quota or threshold is raised, the monitor is unassigned or dropped, or the next interval starts (never, with FREQUENCY = NEVER).

## 5. Why no budget object in pilot 1
Budgets run billed serverless measurement tasks and refresh with up to 6.5 h latency. For a ≤10-credit warehouse-only pilot, the warehouse monitor plus metering views are sufficient. If Stephen wants an account budget anyway, approve it separately; it is not in the plan.

## 6. Shutdown verification (run at the end of every session; Stephen; label each result PASS / FAIL / NOT_RUN)
1. **Stop the recording.** Close every browser tab showing the app, because the WebSocket keeps the warehouse alive.
2. Run these statements:
   ```sql
   ALTER WAREHOUSE SZL_EE_WH SUSPEND;            -- errors harmlessly if already suspended
   ALTER WAREHOUSE SZL_EE_WH SET AUTO_RESUME = FALSE;
   SHOW WAREHOUSES LIKE 'SZL_EE_WH';             -- expect state SUSPENDED, auto_resume false
   SHOW WAREHOUSES;                                   -- every warehouse SUSPENDED (pre-existing ones unchanged)
   SHOW TASKS IN ACCOUNT;                             -- expect none targeting SZL_EE_WH; none created by pilot
   SHOW COMPUTE POOLS;                                -- expect none created by pilot
   SHOW STREAMLITS IN ACCOUNT;                        -- only EVIDENCE_EXPLORER from this pilot
   SHOW RESOURCE MONITORS LIKE 'SZL_EE_RM';         -- used credits vs quota
   ```
3. Usage reconciliation. ACCOUNT_USAGE latency is up to 3 h, and up to 6 h for cloud services, so re-run these after that delay before closing the report. Each query itself briefly resumes a warehouse. Run them in an approved window and **then repeat steps 1–2**.
   ```sql
   SELECT start_time, end_time, credits_used, credits_used_compute, credits_used_cloud_services
   FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
   WHERE warehouse_name = 'SZL_EE_WH' AND start_time >= '<WINDOW_OPEN_UTC>'
   ORDER BY start_time;
   SELECT timestamp, event_name, event_reason, event_state
   FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_EVENTS_HISTORY
   WHERE warehouse_name = 'SZL_EE_WH' AND timestamp >= '<WINDOW_OPEN_UTC>'
   ORDER BY timestamp;
   SELECT usage_date, service_type, credits_used, credits_billed
   FROM SNOWFLAKE.ACCOUNT_USAGE.METERING_DAILY_HISTORY
   WHERE usage_date >= '<WINDOW_OPEN_DATE>' ORDER BY usage_date;
   ```
   Column names come from the docs. METERING_DAILY_HISTORY and WAREHOUSE_EVENTS_HISTORY columns were not re-fetched this session, so verify them before running.
4. Record the remaining trial balance in the Snowsight billing page. Compare it with the pre-flight value (P1) and with the metering totals. Report the difference as **unreconciled**, not zero, if the latency window has not passed.
5. **No promise of zero future charges.** A suspended warehouse and a stopped app do not guarantee zero further charges. Storage (Time Travel / Fail-safe), cloud-services activity, metadata queries, pre-existing resources, and any later visit to the app URL (if AUTO_RESUME were re-enabled) can still incur cost.
6. **Never delete as a cleanup shortcut.** DROP, TRUNCATE or DELETE need separate object-specific approval (DEPLOYMENT_PLAN AP-G2).
