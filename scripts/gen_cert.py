"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
raise NotImplementedError("students: implement cert issuance")
# scripts/gen_cert.py
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
import datetime

def gen_cert(cn: str, ca_dir: Path, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    ca_key = serialization.load_pem_private_key((ca_dir / "ca_private_key.pem").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((ca_dir / "ca_cert.pem").read_bytes())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    out_key = out.with_suffix(".key.pem")
    out_cert = out.with_suffix(".cert.pem")
    out_key.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    out_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print("Wrote", out_key, out_cert)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--cn", required=True)
    p.add_argument("--ca-dir", default="certs")
    p.add_argument("--out", required=True)
    args = p.parse_args()
    gen_cert(args.cn, Path(args.ca_dir), Path(args.out))
