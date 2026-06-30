# User-Level (HKCU) Chrome Policies — Admin Guide

> Operational guide for the **per-user** Chrome policy feature introduced in
> [ADR-002](./adr-002-policy-livello-utente.md). Read this before assigning any
> policy with **Target = User**.

## 1. The two orthogonal axes

Chrome reads policies from **four** registry destinations, derived from two
independent axes you control on every assignment:

| | **Mandatory** (enforced) | **Recommended** (default, user-overridable) |
|---|---|---|
| **Machine** (`Target = Machine`) | `HKLM\SOFTWARE\Policies\Google\Chrome` | `HKLM\…\Chrome\Recommended` |
| **User** (`Target = User`) | `HKCU\SOFTWARE\Policies\Google\Chrome` | `HKCU\…\Chrome\Recommended` |

- **Scope** (`Mandatory` / `Recommended`) = *enforcement level*.
- **Target** (`Machine` / `User`) = *registry hive / who it follows*.

A **Machine** assignment's group is interpreted as a **device group** (resolved
via the device's Entra group membership). A **User** assignment's group is
interpreted as a **user group** (resolved via the logged-on user's
`transitiveMemberOf`). Picking the wrong group type is the most common mistake —
the Admin UI shows a **Machine/User badge** and a warning to help avoid it.

## 2. Precedence — which value wins

When the **same policy key** is set in more than one place, Chrome (not CPM)
decides the winner:

1. **Mandatory always beats Recommended**, regardless of hive.
2. For the **same key at Mandatory level**, **Machine (HKLM) beats User (HKCU)**.
   (Unless you explicitly enable `CloudPolicyOverridesPlatformPolicy` / similar —
   out of scope here.)
3. CPM's **`Priority`** (lower wins) only orders assignments **inside the same
   bucket** (same Target *and* same Scope). It does **not** arbitrate between
   Machine and User — that is Chrome's job.

> ⚠️ **Counter-intuitive result:** if you set `HomepageLocation` as a *User*
> mandatory policy **and** as a *Machine* mandatory policy, the **Machine** value
> wins and your user policy appears to be ignored. This is by design.

## 3. Best practices — avoid overlap

- **Don't set the same key at both Machine and User.** Decide, per policy,
  whether it is a *device* trait or a *person* trait, and assign it in exactly
  one Target.
- **Use User policies for person/identity-bound settings** (e.g. profile-related
  behavior, role-specific configuration on shared/VDI hosts).
- **Use Machine policies for device-wide guarantees** that must hold no matter
  who logs on (security baselines, hard restrictions).
- **Prefer `Recommended` for User policies** you want users to be able to adjust;
  reserve `Mandatory` for settings that must not be changed.
- **One group, one intent.** Keep "device groups" and "user groups" separate in
  Entra; never reuse a device group for a `Target = User` assignment.
- **Watch the key-overlap warning** in the assignment dialog and the precedence
  rules above before shipping a User assignment that touches a key already
  governed at Machine level.

## 4. How User policies are delivered

The machine remediation runs as **SYSTEM** and cannot write a user's `HKCU`.
For every interactive logon it therefore:

1. Enumerates logged-on interactive users (via `explorer.exe` owners).
2. Stages [`Apply-UserChromePolicy.ps1`](../src/Client/Apply-UserChromePolicy.ps1)
   to a world-readable path and grants the user **temporary** read access to the
   device certificate's private key (for mTLS).
3. Runs the user script through a **transient scheduled task** as that user. The
   task:
   - resolves the user's UPN natively (`whoami /upn`),
   - corroborates the **Entra device + PRT** binding via `dsregcmd /status`
     (anti-spoofing, ADR-002 §8),
   - calls `GET /api/v2/users/{upn}/effective-policy`,
   - writes `HKCU\…\Chrome[\Recommended]`, maintains a per-user manifest, and
     removes stale keys,
   - drops a result JSON the SYSTEM orchestrator reads back.
4. Revokes the temporary key ACL and aggregates per-user outcomes.

If a user is **not** a member of any `Target = User` assignment, the endpoint
returns empty buckets and **no policy is written** — any previously-applied HKCU
keys for that user are removed (clean unassignment / logoff hygiene).

## 5. Monitoring

The **Device Monitoring → User Policies** tab shows the latest HKCU compliance
state per **(device, user)** pair: status, applied hash, keys written/removed,
last contact, and any error. Machine and user states have **independent ETags**,
so user-policy churn never invalidates machine-policy caching (and vice-versa).

## 6. Multi-session / VDI

The model is multi-session by design: each interactive session gets its own
scheduled-task run and its own user-policy set based on that user's groups.
Shared hosts, AVD, and RDS are covered natively.

---

*See [ADR-002](./adr-002-policy-livello-utente.md) for the full design rationale.*
