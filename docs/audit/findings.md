# Audit findings — 2026-10-30

Scope: network safety for the dual-homed development laptop, router and endpoint write paths, discovery, agent setup. The broader feature status is in [progress](../progress.md). "Verified" here means automated tests with fake routers, not hardware.

| # | Severity | Finding | Root cause | Status / evidence |
|---|---|---|---|---|
| 1 | Critical | On the development laptop the internet LAN (`10.20.0.0/16`) was a permitted router destination | Code default `ROUTER_ALLOWED_NETWORKS` covers all private ranges, and `bootstrap.sh` never wrote the setting | **Fixed**: bootstrap writes the `/24` around `LAN_IP` (override `ROUTER_NETWORKS`); `scripts/netcheck.py` reports overlap as `CRITICAL`; `test_netcheck.py` |
| 2 | Critical | With Wi-Fi down, a Network B router IP is routed out of the Ethernet gateway | Host routing; the connector does not choose an interface (it cannot inside Docker) | **Mitigated**: TLS verification already keeps credentials from reaching an impostor; `netcheck.py --target` refuses such routes; documented in [dual-network setup](../development/dual-network-setup.md) |
| 3 | High | No real read-only / dry-run / test mode; write gates were scattered across four modules with no transport-level backstop; endpoint changes were outside them | Feature flags were added per subsystem | **Fixed**: `services/safety.py` (`OPERATION_MODE`, `GuardedRouter`, endpoint and signed agent-mode gating); 10 tests in `test_safety_modes.py` |
| 4 | High | Dashboard published on `0.0.0.0` when `LAN_BIND_IP` was missing | Compose fallback | **Fixed**: fallback is `127.0.0.1` |
| 5 | High | A second agent (Codex) was editing the tree while tests ran; the result was intermittent test failures and a half-written disk-repartitioning workflow (`services/storage.py`, `api/storage.py`) | Two agents working at once | Codex stopped. The storage files stay **unmounted**: they need a missing `storage_changes_enabled` setting, a Windows executor and result wiring, and they conflict with the "no automatic disk migration" invariant until recovery and integrity tests exist. Needs an owner decision |
| 6 | Medium | No inventory of non-enrolled devices across DHCP, ARP and Wi-Fi; no way to mark printers or infrastructure | Only Wi-Fi registrations were listed | **Implemented**: `/network/inventory` (stored snapshots only, no scanning) plus descriptive labels; `test_inventory.py`, frontend test |
| 7 | Medium | Docker turns IPv4 forwarding on, and Tailscale is installed on the laptop | Host tooling | **Documented and checked**: netcheck warns; Docker's `FORWARD` policy is `DROP`; Tailscale was logged out with no advertised routes when checked |
| 8 | Medium | "One-click" onboarding: no captive or enrollment portal yet; enrollment needs an admin-issued token and a protected provisioning file | Not implemented | **Open**. A browser cannot install an `.exe`; see the limits in [enrollment](../enrollment.md). A HotSpot/walled-garden design needs the real RouterOS topology first |
| 9 | Low | Developer admission profiles (backend by Codex) have no dashboard UI | Unfinished work | **Open** |
| 10 | Low | `/network/clients` and `/network/inventory` load every enabled device per request | Simple implementation | Acceptable for hundreds of devices; revisit with fleet-size measurements |

Not verified in this session: .NET agent build (no SDK on this machine), Compose smoke, any real router, AP or Windows computer.
