"""
Self-signed HTTPS certificate for the Control Unit (no OpenSSL needed, works on Windows).
Phones only allow GPS on HTTPS pages, so run the server with --https for the handheld.
The certificate covers localhost and every IPv4 address of this laptop.
"""
import datetime
import ipaddress
import os
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def local_ips():
    ips = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:   # the address used for the default route (the Wi-Fi IP)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ips)


def ensure_cert(cert_dir):
    os.makedirs(cert_dir, exist_ok=True)
    crt, key = os.path.join(cert_dir, "cert.pem"), os.path.join(cert_dir, "key.pem")
    ips = local_ips()
    if os.path.exists(crt) and os.path.exists(key):
        c = x509.load_pem_x509_certificate(open(crt, "rb").read())
        have = {str(x) for x in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                .get_values_for_type(x509.IPAddress)}
        if set(ips) <= have and c.not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc):
            return crt, key
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "REVELATION Control Unit"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Team REVELATION")])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(k, hashes.SHA256()))
    with open(key, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    with open(crt, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  created HTTPS certificate for {', '.join(['localhost'] + ips)}", flush=True)
    return crt, key


if __name__ == "__main__":
    print(ensure_cert(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")))
