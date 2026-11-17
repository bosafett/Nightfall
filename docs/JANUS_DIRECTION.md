# JANUS — long-term architectural direction

**Private Security Operations Center (SOC)**
Effective: November 17, 2026 · Status: standing product direction

## 1. Strategic direction

JANUS is being developed into a private, single-operator Security Operations Center (SOC). Its purpose is to provide
one unified environment for monitoring, assessing, detecting, investigating, responding to, and recovering the
owner's infrastructure.

This is the long-term architectural direction for JANUS. It does not authorize an immediate expansion of the active
development scope.

## 2. Operational pillars

JANUS will ultimately coordinate five operational capabilities:

1. **Monitor** — endpoint, server, network, and infrastructure visibility.
2. **Detect and investigate** — intrusion detection, threat indicators, event correlation, incident analysis, and
   evidence collection.
3. **Assess** — authorized security testing, controlled validation, and adversarial exercises through SWORD and
   WARPATH.
4. **Respond and recover** — defensive containment, approved countermeasures, incident response, recovery, and
   verification through SHIELD.
5. **Intelligence and governance** — centralized authorization, auditability, evidence, workflows, AI-assisted
   analysis, and operational history through JANUS CORE and its supporting components.

## 3. Architectural requirements

- Preserve modular, independently deployable sensors.
- Support enrollment of additional owner-controlled computers and servers without redesigning the platform.
- Keep authorization, identity, approval, incident, and audit governance centralized.
- Correlate observations from multiple authorized sources into a unified incident picture.
- Distinguish confirmed findings, hypotheses, unknowns, and completed actions.
- Preserve evidence integrity and traceability.
- Avoid duplicate subsystems when existing JANUS capabilities already fulfill the requirement.
- Design future capabilities to integrate with the existing architecture rather than create parallel platforms.

## 4. Non-negotiable boundaries

- Authorized infrastructure only.
- Defensive operations only. No hacking back or unauthorized activity against third-party infrastructure.
- Human approval for consequential infrastructure-changing actions.
- AI agents cannot grant themselves permissions.
- No unapproved paid services, provider migrations, hosting requirements, or paid AI usage.
- Preserve the public repository and current Vercel/Neon deployment.
- Database migrations remain subject to explicit owner approval before pushing.
- Existing phase gates and security review requirements remain in force.

## 5. Development governance

This direction is not permission to interrupt or expand the current SHIELD v3 Phase 2 implementation. The immediate
priority remains:

1. Complete CrowdSec sensor integration and GUARD.
2. Validate every Phase 2 safeguard.
3. Complete the independent BLACKSITE security review and resolve outstanding review conditions.
4. Validate existing SWORD and SHIELD functionality.
5. Plan subsequent endpoint, server, and network-monitoring capabilities.

Future phases must be separately scoped, reviewed, and approved.

## 6. Product north star

JANUS should ultimately be able to explain:

- What happened?
- Where did it happen?
- What evidence supports the finding?
- What does JANUS know versus suspect?
- What infrastructure is affected?
- What actions have already been taken?
- What actions are recommended?
- What remains unknown?
- What requires operator authorization?

The objective is not to accumulate security features. The objective is to build a reliable, auditable, unified
security operations capability for infrastructure under the owner's control.
