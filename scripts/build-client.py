#!/usr/bin/env python3
"""Build SuroSetup.exe, the one-file Suro Client installer, on Linux or Windows. No code-signing certificate needed.

    python3 scripts/build-client.py                     # 64-bit + 32-bit, version from the agent project
    python3 scripts/build-client.py --arch x64          # smaller file, 64-bit Windows only
    python3 scripts/build-client.py --site site.json    # bake server settings in (only needed for a signed setup)

See docs/developers/building-the-client.md. Nothing is installed, deployed or sent anywhere.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent/src/NetworkPolicyClient.csproj"
UI = ROOT / "agent/ui/Suro.Identity.UI.csproj"
SETUP = ROOT / "agent/setup/SuroSetup.csproj"
PAYLOAD = ROOT / "agent/setup/payload"
STAGING = ROOT / "artifacts/client"
SITE_KEYS = {"server", "signing_public_key", "agent_publisher_thumbprint", "server_certificate_sha256", "ui_language"}


def project_version():
    match = re.search(r"<Version>(\d+\.\d+\.\d+)</Version>", AGENT.read_text(encoding="utf-8"))
    return match.group(1) if match else "0.0.0"


def run(command):
    print("+", " ".join(str(c) for c in command), flush=True)
    subprocess.run([str(c) for c in command], cwd=ROOT, check=True,
                   env={**os.environ, "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_NOLOGO": "1"})


def validate_site(path):
    """Same rules as the setup, the MSI build and the agent: HTTPS, a public key, nothing else (never a token)."""
    site = json.loads(Path(path).read_text(encoding="utf-8"))
    extra = set(site) - SITE_KEYS
    if extra:
        raise SystemExit(f"site.json may contain only {', '.join(sorted(SITE_KEYS))}; found {', '.join(sorted(extra))}")
    if not str(site.get("server", "")).startswith("https://") or "BEGIN PUBLIC KEY" not in str(site.get("signing_public_key", "")):
        raise SystemExit("site.json needs an https:// server and the PEM signing_public_key")
    return site


def payload(dotnet, arch, version):
    """Agent and identity window published together so they share one bundled .NET runtime."""
    folder = STAGING / arch
    shutil.rmtree(folder, ignore_errors=True)
    for project in (AGENT, UI):
        run([dotnet, "publish", project, "-c", "Release", "-r", f"win-{arch}", "--self-contained", "true",
             f"-p:Version={version}", "-p:PublishSingleFile=false", "-o", folder])
    archive = PAYLOAD / f"payload-{arch}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for file in sorted(p for p in folder.rglob("*") if p.is_file()):
            z.write(file, file.relative_to(folder).as_posix())
    print(f"payload {arch}: {archive.stat().st_size / 2**20:.1f} MiB")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default=project_version(), help="x.y.z (default: agent project version)")
    parser.add_argument("--arch", default="x64,x86", help="comma list of x64 and/or x86 (default: both)")
    parser.add_argument("--site", help="optional site.json to embed (see agent/installer/site.example.json)")
    parser.add_argument("--out", default=str(ROOT / "dist/client"), help="output folder (default: dist/client)")
    parser.add_argument("--dotnet", default=os.environ.get("DOTNET_BIN") or shutil.which("dotnet"))
    args = parser.parse_args()
    if not args.dotnet:
        raise SystemExit(".NET 10 SDK is required; install it or set DOTNET_BIN / --dotnet.")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        raise SystemExit("--version must look like 0.4.0")
    arches = [a.strip() for a in args.arch.split(",") if a.strip()]
    if not arches or set(arches) - {"x64", "x86"}:
        raise SystemExit("--arch accepts x64, x86 or x64,x86")

    shutil.rmtree(PAYLOAD, ignore_errors=True)
    PAYLOAD.mkdir(parents=True)
    if args.site:
        validate_site(args.site)
        shutil.copyfile(args.site, PAYLOAD / "site.json")
    for arch in arches:
        payload(args.dotnet, arch, args.version)

    out = Path(args.out)
    build = STAGING / "setup"
    shutil.rmtree(build, ignore_errors=True)
    run([args.dotnet, "build", SETUP, "-c", "Release", f"-p:Version={args.version}", "-o", build])
    out.mkdir(parents=True, exist_ok=True)
    target = out / "SuroSetup.exe"
    shutil.copyfile(build / "SuroSetup.exe", target)
    shutil.rmtree(PAYLOAD, ignore_errors=True)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    architecture = "any" if len(arches) == 2 else arches[0]
    print(f"\n{target}\n  version {args.version} · {architecture} · {target.stat().st_size / 2**20:.1f} MiB · SHA-256 {digest}")
    print("  Upload it in Software → Packages as kind agent_update, architecture "
          f"'{architecture}', expected version {args.version}; leave the publisher empty (unsigned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
