# Security pass: Phases 5a–6a (2026-11-05)

**Scope:** the diff from `4d3b92b` (Vercel deployment) to the War Room and shell work. That covers the agent
framework, the seven agents, the Tool Gateway, migrations 0008 and 0009, the agents pages, the War Room, the
approvals bell and assessment completion.

**Method:** I read each changed route, gateway rule and query against these questions:
1. Can a workspace member read or change another workspace's data?
2. Can a requester end up approving their own operation?
3. Can collected content or another model's output steer an agent?
4. Can any agent output be presented as verified?
5. Can one request cause unbounded cost?
6. Do secrets or personal data leak into responses or logs?

| Area | Result |
|---|---|
| Tenant isolation | Every new route goes through `ws_permission`, and every query runs under RLS with the workspace set. Agent task and War Room reads are tenant-scoped, and tests cover access from another workspace. Investigator and Adversary resolve assets only inside the project's organization. The worker sets the task's workspace before touching other tables. Its only cross-workspace policies are the existing claim policies on `operations` and `agent_tasks`. |
| Self-approval | Agent-proposed operations, including ones from Director-created tasks, carry the requester of the original run. The approve route refuses that person (`self_approval`). The War Room's `can_decide` is display only, and the route re-checks it. |
| Injection | Target content goes only into neutralized `<data>` blocks. The Director's objectives reach other agents as data, not as their task line. The gateway checks every id the model returns against the set it was actually shown. Injection fixtures cover each agent that reads collected content. |
| Agent output vs. records | Agent findings, paths and relationships are hypotheses, enforced by DB CHECKs. Analyst counts come from the records, and its summary is labelled as AI output and kept out of signed reports. Guardian verdicts are advice and never change status. |
| Cost | **Fixed in this pass:** the hourly limit applied only to runs a person started, so a Director run could create 5 more tasks without being checked against it. The limit now counts every task except Guardian reviews, and the gateway refuses Director tasks past it. Test: `test_director_cannot_fan_out_past_the_hourly_limit`. Upper bound per person-started run: 1 + 5 Director tasks + 8 Guardian reviews per Hunter run. |
| Data exposure | The War Room decision log returns only allowlisted actions and fields, never IP or user agent. Usage numbers are counts from `agent_tasks`. No API key is read or returned anywhere except the provider's SDK client, which reads it from the environment. |
| Secrets in the repo | Gitleaks flagged a fixed benchmark UUID. It was a false positive, now replaced with derived ids, and the fingerprint is recorded in `.gitleaksignore`. |

**Not covered:**
- The real Anthropic provider path. No API key was available, so it is tested with a mocked SDK only.
- The isolated lab and BLACKSITE. Neither is built; both need self-hosting, see review §10d and §16.
