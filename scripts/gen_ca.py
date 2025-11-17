"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
raise NotImplementedError("students: implement CA generation")
# scripts/gen_ca.py
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, BasicConstraints
from cryptography import x509
import datetime
from pathlib import Path

def gen_ca(name: str, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([NameAttribute(x509.NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    # write key and cert
    (outdir / "ca_private_key.pem").write_bytes(
        key.private_bytes(encoding=serialization.Encoding.PEM,
                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                          encryption_algorithm=serialization.NoEncryption()))
    (outdir / "ca_cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))
    print(f"CA generated in {outdir}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--name", default="My Root CA")
    p.add_argument("--out", default="certs", help="output dir")
    args = p.parse_args()
    gen_ca(args.name, Path(args.out))
