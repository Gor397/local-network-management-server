import base64
import hashlib
import json
from datetime import timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from app.db import utcnow


def digest(value: bytes | str):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Vault:
    def __init__(self, settings):
        self.fernet = Fernet(settings.encryption_key)
        self.path = settings.data_dir / "keys"
        self.signer = serialization.load_pem_private_key((self.path / "signing.key").read_bytes(), None)
        self.ca_key = serialization.load_pem_private_key((self.path / "ca.key").read_bytes(), None)
        self.ca = x509.load_pem_x509_certificate((self.path / "ca.crt").read_bytes())

    def seal(self, value):
        return self.fernet.encrypt(value.encode()).decode()

    def open(self, value):
        return self.fernet.decrypt(value.encode()).decode()

    def signed(self, document):
        payload = canonical(document)
        signature = self.signer.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return {"payload": base64.b64encode(payload).decode(), "signature": base64.b64encode(signature).decode(), "algorithm": "RS256"}

    def issue(self, csr_pem, device_id):
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid or not isinstance(csr.public_key(), rsa.RSAPublicKey) or csr.public_key().key_size < 3072:
            raise ValueError("enrollment.invalid_csr")
        now = utcnow().replace(tzinfo=timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)]))
                .issuer_name(self.ca.subject).public_key(csr.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.ca_key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM).decode(), cert.fingerprint(hashes.SHA256()).hex()


def initialize_keys(directory: Path):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("signing", "ca"):
        if (directory / f"{name}.key").exists():
            continue
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        path = directory / f"{name}.key"
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        path.chmod(0o600)
        (directory / f"{name}.pub").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        if name == "ca":
            now = utcnow().replace(tzinfo=timezone.utc)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Suro Device CA")])
            cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .sign(key, hashes.SHA256()))
            (directory / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
