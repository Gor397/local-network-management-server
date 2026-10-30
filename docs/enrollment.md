# Windows installation and enrollment

## Build the native service and MSI

Use a Windows build machine with the .NET 10 SDK, PowerShell 7, and an appropriate trusted code-signing certificate. The WiX SDK is restored during build; cache the toolchain, NuGet packages and runtime packs on a connected machine if the build itself must later run offline.

```powershell
dotnet build agent/src/NetworkPolicyClient.csproj -c Release
dotnet run --project agent/tests/AgentContractTests.csproj -c Release
pwsh -File agent/installer/Build-Installer.ps1 -SigningCertificateThumbprint YOUR_SIGNING_CERT_THUMBPRINT
```

The build script publishes a self-contained `win-x64` application, signs the executable/libraries/bundled scripts, generates WiX file entries, builds the MSI and signs it. A trusted signing certificate is required; the repository contains no production signing key. Optional timestamping is a build-host decision. The MSI build and Windows installation still require Windows validation.

The installed executable is `NetworkPolicyClient.exe`; the service is `LocalNetworkPolicyAgent`. The service is configured for automatic startup. The installation wrapper finishes enrollment and starts it; direct MSI installation alone is not complete provisioning.

## Prepare the server

1. Register the device's hostname, class and actual primary Wi-Fi MAC.
2. Publish and assign its desired policy. Existing computers stay in `AUDIT` mode.
3. Generate the device's short-lived enrollment token.
4. Retrieve the trusted policy-signing public key from `data/keys/signing.pub` through the server console.
5. Establish trust for the management server's TLS certificate on the endpoint.

Use the endpoint's real inventory MAC. A locally administered/randomized MAC is an indicator to review, not proof of an attack. Disable randomization for the managed SSID through an approved Windows/network setup where necessary; no cryptographic trust is derived from MAC alone.

## Protected provisioning file

Start from `agent/installer/provisioning.example.json`. Replace every example value:

```json
{
  "server": "https://192.168.88.10",
  "primary_mac": "00:11:22:33:44:55",
  "token": "SHORT_LIVED_DEVICE_TOKEN",
  "signing_public_key": "FULL_TRUSTED_PEM_PUBLIC_KEY_WITH_ESCAPED_NEWLINES",
  "agent_publisher_thumbprint": "TRUSTED_CODE_SIGNING_CERTIFICATE_THUMBPRINT"
}
```

Keep the file readable only by the installing administrator and SYSTEM, transfer it locally through an approved channel, and remove the original securely after enrollment. The token must not be placed in persistent logs, an MSI property, command-line arguments or a shell history entry.

Run from an elevated Windows PowerShell session:

```powershell
.\agent\installer\Install-Agent.ps1 -MsiPath C:\Staging\SuroAgent.msi -ProvisioningFile C:\SecureStaging\device.json
```

The wrapper checks Windows/build privileges and the MSI publisher, protects installation/state files, configures SCM permissions and starts certificate enrollment. In the dashboard, inspect the pending CSR fingerprint and approve it. The enrollment process retries the same CSR until approval or token expiry.

The Windows identity key is a persistent, non-exportable machine CNG RSA key. The server receives only a CSR and certificate. Confirm in a VM that the resulting certificate/private-key binding remains accessible to SYSTEM after the installing administrator signs out and the machine reboots.

## Verify onboarding

```powershell
Get-Service LocalNetworkPolicyAgent
Get-Content "$env:ProgramData\Lantern\agent.jsonl" -Tail 20
```

Check the device's heartbeat, policy UUID, collected inventory and individual checks in the dashboard. Unknown checks are expected where a supported verifier is not implemented or independent network observations are unavailable. Never change them to passing solely to finish enrollment.

## Upgrades and removal

Use a signed MSI from the pinned publisher and preserve `%ProgramData%\Lantern`, the machine certificate and CNG key. The deployment subsystem can stage an external MSI update task; post-restart version validation is still necessary.

For removal, revoke the device certificate in the server, separately revoke/review network authorization, then use authorized local administrative uninstall tooling. The supplied uninstall script retains local state/identity for recovery. Certificate revocation alone does not disconnect an existing Wi-Fi client.

See [recovery](recovery.md) for break-glass administration. Standard-user service/file protection does not protect against a local administrator, SYSTEM compromise or offline disk access.

## User identification after enrollment

The MSI includes `IdentityUI/SuroIdentity.exe`, a separate Armenian-first user-session program with Russian/English options. It starts through the machine Run registration at interactive login; the installation wrapper also schedules an initial run when an interactive user exists. It never displays UI from the Windows Service.

Full name is required and military rank is optional. The service binds submissions to the local pipe client's real Windows SID/account, saves an outbox under protected `%ProgramData%\Lantern`, and uploads signed reports on reconnection. Reports are user-reported; an administrator separately assigns/verifies an owner. A completed SID is not prompted repeatedly. No logged-in user means pending identification.

Use [the developer sequence diagram](developers/suro-expansion.md) for IPC details. Validate standard-user pipe access, SCM PID authentication, MSI directory permissions, logoff/logon, offline retries, and direct upgrades in Windows VMs before distribution. Existing Windows identity/SCM/path names remain unchanged.

## What onboarding can and cannot prove

| State in Suro | What the server actually knows |
|---|---|
| `NOT_REGISTERED` (Network inventory) | A router reported this MAC/IP; nothing about the software on it |
| `REGISTERED_NOT_ENROLLED` | An administrator registered the device; no certificate has been issued |
| `ENROLLED_NO_HEARTBEAT` | A CSR made with the machine's non-exportable key was approved |
| `AGENT_HEALTHY` / `AGENT_STALE` | Signed heartbeats from that key arrive within / outside the deadline |
| `EXEMPT_UNMANAGED` | A developer/admin exception (MAC-based, so spoofable) |

Downloading an installer or visiting a page proves nothing, and Suro never authorizes a device on that basis. A web page cannot install or run an `.exe` without the user acting and Windows asking for elevation. Unmanaged Windows computers therefore cannot be onboarded silently. The closest realistic flow is a locally hosted, signed MSI plus a short-lived enrollment token, with the administrator approving the CSR. A captive-portal or walled-garden page (MikroTik HotSpot) that offers the installer before granting access is **not implemented**. It would change live HotSpot, DHCP and firewall configuration, so it needs the real RouterOS topology and a separately approved migration plan first.

Printers, phones, Linux machines and network equipment cannot run the agent. Classify them in **Network inventory** and keep any enforcement scoped to managed Windows groups, so that infrastructure is never blocked.
