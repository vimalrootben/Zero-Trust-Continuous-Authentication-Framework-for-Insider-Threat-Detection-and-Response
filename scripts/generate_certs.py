import os
import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Define paths relative to the script location
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(BASE_DIR, "certificates")
MANAGER_CERT_DIR = os.path.join(BASE_DIR, "manager", "certs")

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(MANAGER_CERT_DIR, exist_ok=True)

def generate_ca():
    print("Generating Root CA...")
    # Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    
    # Define CA subject and issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustEDR"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Zero Trust EDR Root CA"),
    ])
    
    # Create the self-signed certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save CA private key
    ca_key_path = os.path.join(CERT_DIR, "ca.key")
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save CA cert
    ca_cert_path = os.path.join(CERT_DIR, "ca.crt")
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
    print(f"Root CA generated: {ca_cert_path}")
    return ca_key, ca_cert

def generate_manager_cert(ca_key, ca_cert):
    print("Generating Manager Server Certificate...")
    # Generate manager private key
    manager_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroTrustEDR"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    # Define Subject Alternative Names (SANs)
    sans = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("manager.local"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
    ])
    
    # Create certificate signed by CA
    manager_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(manager_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=True
        )
        .add_extension(sans, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save Manager private key
    manager_key_path = os.path.join(CERT_DIR, "manager.key")
    with open(manager_key_path, "wb") as f:
        f.write(manager_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Save Manager cert
    manager_cert_path = os.path.join(CERT_DIR, "manager.crt")
    with open(manager_cert_path, "wb") as f:
        f.write(manager_cert.public_bytes(serialization.Encoding.PEM))
        
    print(f"Manager cert generated: {manager_cert_path}")
    
    # Copy to manager/certs
    import shutil
    shutil.copy2(manager_key_path, os.path.join(MANAGER_CERT_DIR, "manager.key"))
    shutil.copy2(manager_cert_path, os.path.join(MANAGER_CERT_DIR, "manager.crt"))
    shutil.copy2(os.path.join(CERT_DIR, "ca.crt"), os.path.join(MANAGER_CERT_DIR, "ca.crt"))
    print("Certificates copied to manager/certs/")

if __name__ == "__main__":
    import ipaddress  # Ensure imported
    ca_key, ca_cert = generate_ca()
    generate_manager_cert(ca_key, ca_cert)
    print("Certificate generation complete.")
