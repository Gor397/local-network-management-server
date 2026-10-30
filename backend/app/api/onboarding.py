"""Public local onboarding page for computers that must install the Suro Client.

Served over plain HTTP on the LAN by the proxy's onboarding listener (no certificate warnings, no internet).
It contains no secrets: the installer is the administrator-approved, Authenticode-signed Suro MSI, and the
client enrolls over pinned HTTPS afterwards. Nothing here grants network access.
"""

import html
from ipaddress import ip_address, ip_network
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from sqlalchemy import select
from app.auth.dependencies import db_session
from app.models import Device, NetworkAdmission, SoftwarePackage

router = APIRouter(tags=["onboarding"])

TEXT = {
    "hy": {
        "title": "Suro — Միացում ցանցին",
        "lead": "Այս ցանցից օգտվելու համար անհրաժեշտ է տեղադրել Suro ծրագիրը։",
        "install": "Տեղադրել Suro ծրագիրը",
        "unavailable": "Տեղադրման ֆայլը դեռ պատրաստ չէ։ Դիմեք ադմինիստրատորին։",
        "steps": ["Սեղմեք «Տեղադրել Suro ծրագիրը» կոճակը։", "Բացեք ներբեռնված ֆայլը և Windows-ի հարցմանը պատասխանեք «Այո»։",
                  "Լրացրեք Ձեր անունը, ազգանունը և, առկայության դեպքում, զինվորական կոչումը։",
                  "Սեղմեք «Սկսել աշխատանքը»։ Ադմինիստրատորի հաստատումից հետո ցանցը կբացվի։"],
        "start": "Սկսել աշխատանքը",
        "status": {"AUTHORIZED": "Պատրաստ է։ Այս համակարգիչն արդեն ունի ցանցային հասանելիություն։",
                   "WAITING_APPROVAL": "Suro ծրագիրը տեղադրված է և սպասում է ադմինիստրատորի հաստատմանը։",
                   "AUTHORIZATION_PENDING": "Suro ծրագիրը աշխատում է։ Ցանցը կբացվի մեկ-երկու րոպեից։",
                   "RESTRICTED": "Suro ծրագիրը դեռ չի աշխատում այս համակարգչում։ Տեղադրեք այն կամ դիմեք ադմինիստրատորին։",
                   "UNKNOWN": "Այս համակարգիչը դեռ չի ճանաչվել։ Տեղադրեք Suro ծրագիրը, ապա կրկին սեղմեք։"},
        "trouble": "Եթե ինչ-որ բան չի ստացվում",
        "tips": ["Եթե Windows-ը չի թույլատրում տեղադրումը, դիմեք ադմինիստրատորին. նա կարող է տեղադրել ծրագիրը Ձեր համակարգչում։",
                 "Եթե այս էջն ինքնուրույն չի բացվել, բրաուզերում մուտքագրեք այս էջի հասցեն, որը Ձեզ տվել է ադմինիստրատորը։",
                 "Մի անջատեք հակավիրուսը կամ Windows-ի պաշտպանությունը։ Դա անհրաժեշտ չէ։"],
        "verify": "Ֆայլի ստուգում",
    },
    "ru": {
        "title": "Suro — Подключение к сети",
        "lead": "Чтобы пользоваться этой сетью, установите программу Suro.",
        "install": "Установить программу Suro",
        "unavailable": "Установочный файл ещё не готов. Обратитесь к администратору.",
        "steps": ["Нажмите кнопку «Установить программу Suro».", "Откройте загруженный файл и ответьте «Да» на запрос Windows.",
                  "Укажите имя, фамилию и, если есть, воинское звание.",
                  "Нажмите «Начать работу». После подтверждения администратором сеть откроется."],
        "start": "Начать работу",
        "status": {"AUTHORIZED": "Готово. У этого компьютера уже есть доступ к сети.",
                   "WAITING_APPROVAL": "Программа Suro установлена и ждёт подтверждения администратора.",
                   "AUTHORIZATION_PENDING": "Программа Suro работает. Сеть откроется через минуту-две.",
                   "RESTRICTED": "Программа Suro на этом компьютере пока не работает. Установите её или обратитесь к администратору.",
                   "UNKNOWN": "Этот компьютер ещё не опознан. Установите программу Suro и нажмите снова."},
        "trouble": "Если что-то не получается",
        "tips": ["Если Windows не разрешает установку, обратитесь к администратору: он может установить программу на ваш компьютер.",
                 "Если эта страница не открылась сама, введите в браузере адрес, который дал администратор.",
                 "Не отключайте антивирус и защиту Windows. Это не нужно."],
        "verify": "Проверка файла",
    },
    "en": {
        "title": "Suro — Connect to the network",
        "lead": "To use this network, install the Suro program.",
        "install": "Install the Suro program",
        "unavailable": "The installer is not ready yet. Please contact your administrator.",
        "steps": ["Click “Install the Suro program”.", "Open the downloaded file and answer “Yes” when Windows asks.",
                  "Enter your first name, surname and, if you have one, military rank.",
                  "Click “Start working”. The network opens after an administrator approves the computer."],
        "start": "Start working",
        "status": {"AUTHORIZED": "Done. This computer already has network access.",
                   "WAITING_APPROVAL": "Suro is installed and waiting for an administrator to approve this computer.",
                   "AUTHORIZATION_PENDING": "Suro is running. The network opens within a minute or two.",
                   "RESTRICTED": "Suro is not running on this computer yet. Install it or contact your administrator.",
                   "UNKNOWN": "This computer is not recognised yet. Install Suro, then click again."},
        "trouble": "If something does not work",
        "tips": ["If Windows does not allow the installation, ask your administrator; they can install the program for you.",
                 "If this page did not open by itself, type the address your administrator gave you into the browser.",
                 "Do not switch off antivirus or Windows protection. It is not needed."],
        "verify": "File check",
    },
}

STYLE = """*{box-sizing:border-box}body{margin:0;font-family:'Noto Sans Armenian','Segoe UI',Arial,sans-serif;background:#f3f6f8;color:#20323f}
header{display:flex;justify-content:space-between;align-items:center;padding:18px 24px;background:#10202e;color:#fff;font-weight:700;letter-spacing:2px}
header nav a{color:#bfe6de;margin-left:14px;font-weight:400;letter-spacing:0;text-decoration:none;padding:8px}header nav a[aria-current]{color:#fff;text-decoration:underline}
main{max-width:680px;margin:32px auto;padding:0 16px}section{background:#fff;border:1px solid #e1e8ed;border-radius:12px;padding:28px}
h1{font-size:28px;margin:0 0 10px}p{line-height:1.6;font-size:17px}
.install{display:block;text-align:center;background:#0a8d78;color:#fff;font-size:22px;font-weight:600;padding:20px;border-radius:10px;text-decoration:none;margin:24px 0}
.install:focus-visible,button:focus-visible{outline:4px solid #e8a33c;outline-offset:3px}
ol{font-size:16px;line-height:1.8;padding-left:22px}button{width:100%;font-size:19px;padding:16px;border-radius:10px;border:2px solid #0a8d78;background:#fff;color:#0a6f5f;font-weight:600;cursor:pointer}
#result{min-height:28px;font-weight:600}.warn{background:#fff5e6;border:1px solid #f0d5a6;padding:14px;border-radius:8px}
details{margin-top:20px;font-size:15px}code{word-break:break-all;font-size:12px}"""


def _installer(db):
    return db.scalar(select(SoftwarePackage).where(SoftwarePackage.kind == "agent_update", SoftwarePackage.approved_by.is_not(None))
                     .order_by(SoftwarePackage.created_at.desc()))


@router.get("/onboard", response_class=HTMLResponse)
def page(lang: str = "hy", db=Depends(db_session)):
    lang = lang if lang in TEXT else "hy"
    t, e = TEXT[lang], html.escape
    package = _installer(db)
    nav = "".join(f'<a href="/onboard?lang={code}" lang="{code}"{" aria-current=page" if code == lang else ""}>{name}</a>'
                  for code, name in (("hy", "Հայերեն"), ("ru", "Русский"), ("en", "English")))
    install = (f'<a class="install" href="/onboard/installer" download="SuroSetup.msi">{e(t["install"])}</a>' if package
               else f'<p class="warn" role="alert">{e(t["unavailable"])}</p>')
    messages = "".join(f' data-{k.lower().replace("_", "-")}="{e(v)}"' for k, v in t["status"].items())
    verify = (f'<p>{e(t["verify"])}: SHA-256 <code>{e(package.sha256)}</code>'
              f'{f" · {e(package.publisher_thumbprint)}" if package.publisher_thumbprint else ""}</p>' if package else "")
    body = f"""<!doctype html><html lang="{lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(t["title"])}</title><style>{STYLE}</style></head><body><header><span>SURO</span><nav aria-label="Language">{nav}</nav></header>
<main><section><h1>{e(t["title"])}</h1><p>{e(t["lead"])}</p>{install}<ol>{"".join(f"<li>{e(s)}</li>" for s in t["steps"])}</ol>
<button id="check" type="button">{e(t["start"])}</button><p id="result" role="status" aria-live="polite"{messages}></p>
<details><summary>{e(t["trouble"])}</summary><ul>{"".join(f"<li>{e(s)}</li>" for s in t["tips"])}</ul>{verify}</details>
</section></main><script src="/onboard/check.js"></script></body></html>"""
    return HTMLResponse(body, headers={"Cache-Control": "no-store", "Content-Security-Policy":
                                       "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'"})


CHECK_JS = """document.getElementById('check').addEventListener('click',function(){var out=document.getElementById('result');
fetch('/onboard/status',{cache:'no-store'}).then(function(r){return r.json()}).then(function(s){
out.textContent=out.dataset[(s.state||'UNKNOWN').toLowerCase().replace(/_([a-z])/g,function(m,c){return c.toUpperCase()})]||out.dataset.unknown;
}).catch(function(){out.textContent=out.dataset.unknown;});});"""


@router.get("/onboard/check.js")
def script():
    return Response(CHECK_JS, media_type="text/javascript", headers={"Cache-Control": "no-store"})


@router.get("/onboard/installer")
def installer(request: Request, db=Depends(db_session)):
    package = _installer(db)
    path = request.app.state.settings.data_dir / "repository" / "objects" / package.sha256 if package else None
    if not package or not path.is_file() or path.stat().st_size != package.size:
        raise HTTPException(404, "onboarding.installer_unavailable")
    # Streamed from disk; the whole MSI is never held in memory.
    return FileResponse(path, media_type="application/x-msi", filename="SuroSetup.msi")


def client_ip(request):
    """The browser's address. A forwarded value is believed only from the configured onboarding proxy."""
    peer = request.client.host if request.client else ""
    forwarded = request.headers.get("x-suro-client-ip", "")
    try:
        trusted = any(ip_address(peer) in ip_network(n.strip(), strict=False)
                      for n in request.app.state.settings.trusted_proxy_networks.split(",") if n.strip())
    except ValueError:
        trusted = False
    return forwarded if trusted and forwarded else peer


def _by_router_lease(request, db, ip):
    """Before the agent reports, map the browser's IP to a MAC through the gate router's last stored snapshot."""
    import json
    from app.models import Router
    for admission in db.scalars(select(NetworkAdmission).where(NetworkAdmission.router_id.is_not(None))):
        router = db.get(Router, admission.router_id)
        device = db.get(Device, admission.device_id)
        if not router or not router.snapshot:
            continue
        snapshot = json.loads(request.app.state.vault.open(router.snapshot))
        if any(r.get("address") == ip and str(r.get("mac-address", "")).upper() == device.primary_mac
               for r in snapshot.get("ip/arp", []) + snapshot.get("ip/dhcp-server/lease", [])):
            return admission
    return None


@router.get("/onboard/status")
def status(request: Request, db=Depends(db_session)):
    """Coarse state for the requesting computer only; no names, MACs or other computers are disclosed."""
    from app.services import admission_gate as gate
    from app.services.admission_sync import credential_active, get_policy
    from app.services.devices import effective_state
    from app.models import Enrollment
    from app.db import utcnow
    ip = client_ip(request)
    admission = db.scalar(select(NetworkAdmission).where((NetworkAdmission.granted_ip == ip) | (NetworkAdmission.reported_ip == ip)))
    if not admission:
        admission = _by_router_lease(request, db, ip)
    if not admission:
        return {"state": "UNKNOWN"}
    device = db.get(Device, admission.device_id)
    if not credential_active(db, device):
        pending = db.scalar(select(Enrollment.id).where(Enrollment.device_id == device.id, Enrollment.approved.is_(False),
                                                         Enrollment.csr.is_not(None), Enrollment.expires_at > utcnow()))
        return {"state": "WAITING_APPROVAL" if pending else "RESTRICTED"}
    desired, _ = gate.evaluate(device, admission, get_policy(db), True, effective_state(device, request.app.state.settings)[0])
    state = gate.network_state(admission, desired)
    return {"state": state if state in ("AUTHORIZED", "AUTHORIZATION_PENDING") else "RESTRICTED"}
