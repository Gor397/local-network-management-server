# Mandatory Suro Client (network admission)

A computer under this requirement gets normal network access only while its enrolled Suro Client is running. **The router enforces it**, not Windows. The feature ships with the policy set to `DISABLED`. Only computers an administrator adds as pilot devices are ever gated.

## How it works

| Piece | File |
|---|---|
| Decision (enrolled, agent fresh, optional compliance, exemptions, overrides) | `evaluate()` in `backend/app/services/admission_gate.py` |
| Router rules, grants, feasibility and rollback commands | `backend/app/services/admission_gate.py` |
| Worker that keeps the router's grant in step | `backend/app/services/admission_sync.py` (each worker tick) |
| Admin API | `backend/app/api/admission.py` |
| Local onboarding page and installer download | `backend/app/api/onboarding.py`, nginx `listen 8080` server |
| Dashboard | Network → **Suro Client requirement**; device page → **Network access** |
| Portal enrollment in the agent | `Enrollment/EnrollmentClient.cs` (`RequestOnboarding`), `Enrollment/OnboardingWorker.cs` |

**Gate (installed once per computer, through preview → apply → readback).** These rules go on the router that routes the computer's subnet. Every one matches only that computer's MAC and sits before all existing rules:

```
/ip firewall filter   chain=forward src-mac-address=<MAC> src-address-list=!suro-admitted dst-address=!<Suro IP> action=drop
/ip firewall filter   chain=input   src-mac-address=<MAC> src-address-list=!suro-admitted protocol=tcp action=drop
/ipv6 firewall filter chain=forward src-mac-address=<MAC> action=drop        (only when IPv6 is present)
```

No other device matches, so a pilot cannot restrict anyone else. DHCP, DNS and ICMP to the router still work, and the computer can always reach the Suro server.

**Grant (kept by the worker).** The grant is an entry `suro-admitted <IP> timeout=<heartbeat timeout + grace>`. It is created only when all of these hold:
- the agent is enrolled;
- its *signed* heartbeat reports an IP;
- the router's own ARP or bound DHCP lease ties that IP to the computer's MAC.

It is replaced about every half TTL, and router I/O happens only then. When the agent stops, the worker deletes the grant after timeout + grace (with auto-revoke on). The router also expires it by itself if Suro is down (`outage_policy=EXPIRE`). With `HOLD`, grants have no timeout and Suro revokes them explicitly, so a Suro outage never cuts anyone off.

**Every router write** goes through `GuardedRouter`. That means `OPERATION_MODE` and the per-router write switch apply. `firewall_shape()` also refuses any firewall write that is not a Suro-owned `drop` rule limited to one MAC, or a Suro-owned address-list entry.

**Requested versus applied.** An override or toggle is recorded at once. The **Network access** state comes only from what the router confirmed:

| State | Meaning |
|---|---|
| `AUTHORIZED` | Grant read back and not expired |
| `AUTHORIZATION_PENDING` / `REVOCATION_PENDING` | Decision made, router not yet updated |
| `RESTRICTED` | The gate is dropping the computer's traffic |
| `GATE_NOT_INSTALLED` | Nothing is enforced yet |

### Limits

- **Layer 2:** the router's firewall sees only traffic it forwards or receives. Hosts in the same subnet talk directly. Preview lists them (`admission.same_subnet_not_isolated`). For full isolation, put the pilot laptop on a dedicated pilot SSID/VLAN with its own subnet routed by the same router; then every packet to the protected LAN is routed through the gate. Suro does not create SSIDs or VLANs; that is a router-wide change for you to make deliberately.
- **Wireless peers on the same AP** may still reach each other unless the SSID or datapath disables client-to-client forwarding.
- **MAC is a claim.** The gate keys on MAC because RouterOS 6 CAPsMAN gives no per-client certificate identity without RADIUS. A device that spoofs the pilot's MAC and IP at the same time would share its fate (and collide with it). WPA2-Enterprise/EAP-TLS with RADIUS would be stronger but needs a RADIUS service; it is not part of this pilot.
- **Revocation delay:** up to one worker tick (30–60 s) after timeout + grace. With `EXPIRE`, also at most timeout + grace after Suro stops. Existing connections are dropped too, because the rule sits before the `established` accept.
- **RouterOS transport:** writes need API-SSL (RouterOS 6.43+) or HTTPS REST (RouterOS 7) with a trusted certificate. The live controller is currently reached through the read-only plain API, so preview reports `admission.router_read_only_transport` until that changes.

## Onboarding without internet

1. Build the site installer once, on Windows, with the code-signing certificate:
   `agent/installer/Build-Installer.ps1 -SigningCertificateThumbprint <thumb> -Version 0.3.0 -SiteFile site.json`.
   `site.json` (see `site.example.json`) holds only `server`, `signing_public_key`, `agent_publisher_thumbprint`, `server_certificate_sha256` and `ui_language`. The build refuses anything else, including tokens.
2. Upload the MSI as an `agent_update` package and approve it. The onboarding page offers the newest approved one.
3. Expose the page: set `ONBOARDING_HTTP_BIND=<server LAN IP>:80` and restart the web container. It serves only `/onboard`; every other path redirects there. It is plain HTTP on purpose: there is no certificate to warn about, the page holds no secret, and the MSI is Authenticode-signed. Users type `http://<server IP>`, or a name you add as a static DNS entry on the router. Captive-portal detection does not work without internet, so tell users the address.
4. When the laptop's client starts without an identity, it locks `%ProgramData%\Lantern` to SYSTEM/Administrators, then asks `/agent/onboarding-request` with its CSR and MACs. The server answers with a token only while an administrator has opened **Allow client installation** for that computer. An administrator then approves the request on the device page (Enrollments). Only then is a certificate issued, the service restarts as the agent, and the registration window (first name, surname, optional rank; Armenian by default) opens for the signed-in user.

A technician can still preinstall with `Install-Agent.ps1` and a short-lived token, as before.

## Testing one laptop

Prerequisites: the router that routes the laptop's subnet is registered with API-SSL or REST and write switch on. `OPERATION_MODE=controlled_test` names that router in `TEST_ROUTERS`. `MANAGEMENT_ADDRESS` is the Suro server's LAN IP. You have WinBox or console access to the router through a path that does not depend on the laptop. Back up the router (`/export` and a binary backup) before step 4.

1. **Policy:** Network → Suro Client requirement → Enforcement mode **Pilot devices only** → Save (reason).
2. **Laptop:** **Add pilot laptop** → enter the laptop's Wi-Fi MAC (turn off random hardware addresses for this SSID on the laptop) and choose the router.
3. **Check:** in the table, select the laptop → **Prepare router gate**. Read the router facts. Resolve every blocker. Note the same-subnet warning; if you need real isolation, move the laptop to a pilot SSID/VLAN first.
4. **Apply:** **Apply to router**. Network access becomes *Restricted to onboarding*. The laptop can open `http://<Suro IP>` but nothing routed.
5. **Install:** **Allow client installation** (e.g. 120 minutes). On the laptop open the onboarding page, click **Տեղադրել Suro ծրագիրը**, run the MSI and accept UAC.
6. **Approve:** on the device page (Overview → Enrollments) approve the request; check the hostname and CSR fingerprint first. The registration window appears on the laptop; the user enters their name.
7. **Verify:** within a minute or two Network access shows *Authorized (router confirmed)*, with the granted IP and expiry. On the router, `/ip firewall address-list print where list=suro-admitted` shows the entry. Routed resources work from the laptop.
8. **Enforcement check:** stop the `LocalNetworkPolicyAgent` service on the laptop. After timeout + grace (default 10 minutes) the state returns to *Restricted* and routed access stops. Start it again: access returns after the next heartbeat and worker tick.
9. **Disable / roll back:** **Stop requiring the client** restores access at once (a permanent grant). Then **Remove gate and restore access** → Apply removes only this laptop's rules. If Suro is down, paste the commands under **Emergency rollback at the router** into the router terminal.

## Cases

| Case | Behavior | Evidence |
|---|---|---|
| A new laptop | Restricted → onboarding page → approved enrollment → grant | `test_portal_enrollment_*`, `test_pilot_gate_*` |
| B client installed | Signed heartbeat + router-confirmed IP → grant, no reinstall | `test_pilot_gate_*` |
| C uninstalled / D stopped | No heartbeat → `agent_offline` after timeout + grace → grant removed | `test_pilot_gate_*`, `test_decisions_*` |
| E developer | Exempt only when an administrator sets it; audited | `test_developer_exemption_*` |
| F Suro outage | `EXPIRE`: router timeout; `HOLD`: kept. Infrastructure is never gated | `test_decisions_*` |
| G spoofed MAC | Reported IP must match the router's ARP/lease for that MAC; enrollment needs an open window and approval | `test_unconfirmed_ip_*`, `test_portal_enrollment_*` |
| H reinstalled Windows | **Reset enrollment** revokes the old certificate; the portal then accepts a new request | `test_portal_enrollment_*` |
| I several adapters | The agent sends all Ethernet/Wi-Fi MACs; the gate uses the device's primary MAC. Random per-network MACs must be off for the pilot SSID | design |
| J failed install | Page stays reachable; **Authorize temporarily** gives timed access for repair | UI |
| K noncompliant | Authorized unless *Require policy compliance* is on | `test_decisions_*` |

Static IP: onboarding uses the restricted network's normal DHCP. The final address comes later from the policy (detected, see [policy editor](policy-editor.md)). The gate follows the address the router confirms, so an address change re-issues the grant rather than locking the computer out.

## Network-wide later

`GROUPS` and `ALL` are refused (`admission.mode_requires_staged_rollout`). Per-MAC rules do not scale to hundreds of computers on an old router. The planned design is one subnet-level drop rule per managed subnet, with `suro-admitted` and an exemption list for developers and infrastructure. It also needs a preview of every affected host, a staged group rollout and a one-step rollback. The decision code (`evaluate`) and the grant worker already work per computer and need no change.

Resource cost: no new service and no RADIUS. Per gated computer the worker makes one address-list read plus a delete and add per refresh, about every five minutes with the defaults.
