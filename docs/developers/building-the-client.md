# Building and distributing the Suro Client

The Suro Client is the Windows service (`agent/src/`) plus the identity window (`agent/ui/`). Both ship in one file, **`SuroSetup.exe`**. You build it once, upload it to Suro, and people install it from the onboarding page with a single button.

You do **not** need a code-signing certificate, WiX, a Windows build machine, or a `site.json` per server. Code signing is optional (see [Optional: a code-signed setup](#optional-a-code-signed-setup)).

| | |
|---|---|
| Target computers | Windows 10 version 1607 (build 14393) or later, and Windows 11. **64-bit and 32-bit**, both in the same file. |
| Build machine | Linux or Windows with the .NET 10 SDK and Python 3. Internet is needed only to download NuGet packages during the build. |
| Result | `dist/client/SuroSetup.exe`, about 95 MB (both architectures) or about 50 MB (`--arch x64`) |

## 1. Build

Install the .NET 10 SDK once: `dotnet-install.sh --channel 10.0` on Linux, or the installer on Windows. If `dotnet` is not on your `PATH`, set `DOTNET_BIN` to its full path. Then, from the repository root:

```sh
make client                       # same as: python3 scripts/build-client.py
make client ARCH=x64              # 64-bit Windows only: half the size
python3 scripts/build-client.py --version 0.4.1   # override the version (default: agent/src project version)
```

The script prints the file path, version, architecture (`any`, `x64` or `x86`), size and SHA-256. It does not install, upload or contact anything.

What it does:

1. For each architecture, it publishes the service (`NetworkPolicyClient`) and the identity window (`SuroIdentity`) self-contained into one folder, so they share one bundled .NET runtime. Windows needs no .NET installed.
2. It zips each folder into `agent/setup/payload/payload-<arch>.zip`.
3. It builds `agent/setup/SuroSetup.csproj`, a small .NET Framework 4.6.2 program that every Windows 10/11 already has, with those zips embedded.
4. It deletes the temporary payload folder. Intermediate output stays in `artifacts/client/` (ignored by git).

## 2. Publish it on the Suro server

1. Dashboard → **Software → Packages** → upload `SuroSetup.exe`.
   - Kind: `agent_update`
   - Architecture: `any` (or `x64` / `x86` if you built only one)
   - Expected version: the version the script printed (for example `0.4.0`)
   - Publisher: leave empty for an unsigned build
   - Minimum Windows build: `14393`
2. Approve the package. The onboarding page always offers the newest approved `agent_update` package.
3. In `.env`, `PUBLIC_ORIGIN` must be the HTTPS address computers use to reach Suro, for example `https://192.168.88.10` (not `localhost`). Set `ONBOARDING_HTTP_BIND=<server LAN IP>:80` so the plain-HTTP onboarding page is reachable.

**How the setup knows your server.** When someone downloads the setup from the onboarding page, Suro appends its own public settings to the end of the file: server address, policy-signing public key, TLS certificate fingerprint, and the language chosen on the page. They contain no token or other secret. The same uploaded file therefore works for any Suro server. Administrators can view the values at `GET /api/v1/admission/site-config`.

## 3. What a user does

1. Open `http://<Suro server IP>` (or the DNS name you gave it). Any address redirects to the onboarding page.
2. Click **Տեղադրել Suro ծրագիրը / Установить программу Suro / Install the Suro program**.
3. Open the downloaded file from the browser's download bar, then answer **Yes** to the Windows prompt.
4. A small window shows progress and then says the program is installed. After an administrator approves the computer, a window asks for first name, surname and rank.

A web page cannot start a program by itself. That is a browser security rule, so step 3 always needs one click on the downloaded file. Everything after that is automatic.

Windows may also show two standard prompts:

- **User Account Control.** Installing a service needs administrator rights. On a standard-user account, Windows asks for an administrator password. In that case a technician installs it, or deploys `SuroSetup.exe /quiet` through your usual tooling.
- **SmartScreen** ("Windows protected your PC") for an unsigned file downloaded through a browser: the user clicks **More info → Run anyway**. The onboarding page explains this in all three languages. A code-signed setup from a publisher Windows already trusts avoids it.

## 4. What the setup changes on the computer

| Item | Where |
|---|---|
| Program files (service, identity window, scripts, runtime) | `C:\Program Files\Lantern Policy Agent\`. Users: read/execute only; SYSTEM and Administrators: full control |
| Device identity and state (kept on update and uninstall) | `C:\ProgramData\Lantern\`. SYSTEM and Administrators only |
| Server settings | `site.json` next to the service; copied to `ProgramData\Lantern\config.json` on first start |
| Integrity record | `ProgramData\Lantern\install-manifest.json` (SHA-256 of the client's own files) |
| Windows service | `LocalNetworkPolicyAgent`, LocalSystem, automatic start, restart on failure; only Administrators can stop or reconfigure it |
| Sign-in entry | `HKLM\…\Run\SuroIdentification` (identity window in the user's session) |
| Uninstall entry | Settings → Apps → **Suro Client** (`Setup\Uninstall-Suro.ps1`) |
| Log | `ProgramData\Lantern\setup.log` |

Running the setup again repairs or updates the installation. It never touches existing accounts, firewall rules or disks. It refuses a `config.json` that was not created by SYSTEM or an administrator.

The setup picks the payload that matches Windows: 64-bit or 32-bit. Windows on ARM is not a tested target.

## 5. Updating installed clients

Build a higher version (`--version 0.4.1`, or raise `<Version>` in `agent/src/NetworkPolicyClient.csproj`), upload and approve it as above, then deploy it to computers or groups from **Software → Deployments**. The agent checks the SHA-256 from the server-signed task, then runs `SuroSetup.exe /quiet` from a SYSTEM scheduled task outside the service. A client installed from a signed build stays pinned to that publisher.

## 6. How integrity works without a certificate

| Check | Unsigned build | Signed build |
|---|---|---|
| Download from onboarding page | Plain HTTP on the local network; same trust as the page | Authenticode publisher shown by Windows |
| Agent updates | SHA-256 in the server-signed task manifest | SHA-256 and pinned Authenticode publisher |
| Bundled PowerShell scripts | Compared byte-for-byte with the copy embedded in the service at build time, then run with `-ExecutionPolicy Bypass`; a changed script is refused | `-ExecutionPolicy AllSigned` |
| `agent.integrity_valid` evidence | Files match `install-manifest.json` | Authenticode publisher of the service executable |

These checks detect changes made after installation by anyone who is not an administrator. As everywhere in Suro, a local administrator is not prevented from tampering with the client.

## Optional: a code-signed setup

If you have a code-signing certificate, a signed setup avoids SmartScreen and keeps publisher pinning for updates.

1. Download `site.json` as an administrator from `GET /api/v1/admission/site-config` and add `"agent_publisher_thumbprint": "<certificate thumbprint>"`.
2. Run `python3 scripts/build-client.py --site site.json`. A signed file must carry its settings inside, because Suro does not append to signed files.
3. Sign `dist/client/SuroSetup.exe` with `signtool sign /fd SHA256 /sha1 <thumbprint> /tr <timestamp URL> /td SHA256`.
4. Upload it with the publisher thumbprint filled in.

Do not put the certificate password or private key in command arguments or logs. The older WiX MSI path (`agent/installer/Build-Installer.ps1`, 64-bit only, Windows build machine, signing required) still works for technicians who preinstall with `Install-Agent.ps1` and a token.

## Who must install it

Choosing computers is done in the dashboard under **Network → Suro Client requirement**. Details are in [client-admission](client-admission.md).

- **One computer.** Use **Add computer by MAC**.
- **A list of computers.** Tick them in the table, choose **Require the client for selected**, then **Prepare router plan for selected computers**. One reviewed router plan covers up to 50 computers.
- **All computers except exceptions.** Set the policy mode to *All computers of chosen networks*, add each network (for example `192.168.88.0/24`), and put printers, cameras and similar devices under **Exceptions**. Before anything is blocked, the preview lists every host that would lose access, and you confirm by typing that number.

## Troubleshooting

| Message | Meaning |
|---|---|
| `SURO-01` no server settings | The file was not downloaded from the onboarding page, and the computer has no earlier installation. Download it from the page. |
| `SURO-02` | Windows older than 10 version 1607 |
| `SURO-03` | The build does not contain this architecture (for example an `--arch x64` build on 32-bit Windows) |
| `SURO-04` | Damaged or unexpected server settings |
| `SURO-05` | A `ProgramData\Lantern` file was created by a non-administrator; it is not trusted |
| `SURO-07` | `sc.exe` failed to register the service; see `setup.log` |
| `SURO-08` | The service did not start; see Event Viewer → Application → `LocalNetworkPolicyAgent` |
| Page says the installer is not ready | No approved `agent_update` package, or `PUBLIC_ORIGIN` is `localhost` (`onboarding.public_origin_not_reachable`) |

## Verification status

The build, the cross-compiled service, identity window and setup, and the script-integrity contract tests run on Linux (`python3 scripts/dev-check.py --area agent`). Install, update, uninstall, SmartScreen/UAC behavior, 32-bit Windows 10 and the Windows service itself have **not yet been run on Windows**. Use the [Windows VM matrix](testing.md) before relying on them.
