from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, AuthorityInformationAccessOID
from cryptography.x509.general_name import UniformResourceIdentifier
import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "private\\ca_cert.pem"), "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

with open(os.path.join(BASE_DIR, "private\\ca_key.pem"), "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

crl_path  = os.path.join(BASE_DIR, "public\\eshark_f.crl")

def generate_csr(subject_info):
    # Sample:
    # subject_info = {
    #     "country_name": "CN",
    #     "state_or_province_name": "Beijing City",
    #     "locality_name": "Beijing City",
    #     "organization_name": "Tsinghua", 
    #     "common_name": "Baron",
    #     "email_address": "",
    # }
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject_attributes = []
    
    oid_mapping = {
        "country_name": NameOID.COUNTRY_NAME,
        "state_or_province_name": NameOID.STATE_OR_PROVINCE_NAME,
        "locality_name": NameOID.LOCALITY_NAME,
        "organization_name": NameOID.ORGANIZATION_NAME,
        "common_name": NameOID.COMMON_NAME,
        "email_address": NameOID.EMAIL_ADDRESS,
    }

    for key, value in subject_info.items():
        if value:
            if key != 'email_address':
                subject_attributes.append(x509.NameAttribute(oid_mapping[key], value))

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(subject_attributes)
    ).sign(private_key, hashes.SHA256())

    return [private_key, csr]

def issue_cert(csr, valid_period=datetime.timedelta(days=365)):
    valid_from=datetime.datetime.now(datetime.timezone.utc)
    valid_to = valid_from + valid_period
    cert_builder = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,  # nonRepudiation
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
    ).add_extension(
        x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.5.1.1"), [])]), critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
    ).add_extension(
        x509.SubjectAlternativeName([x509.RFC822Name(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value),]), critical=False
    ).add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                UniformResourceIdentifier(u"http://ca.f.eshark.cc/public/eshark_f.crt")
            ),
        ]),
        critical=False
    ).add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[UniformResourceIdentifier(u"http://ca.f.eshark.cc/public/eshark_f.crl")],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ]),
        critical=False
    )
    signed_cert = cert_builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256()
    )

    return signed_cert


def update_crl(revokeCertsInfo):
    # revokeCertInfo = {
    #     "serial_number": "123456",
    #     "revocation_date" : datetime(),
    #     "crl_reason": 0,
    # }
    
    reason_map = {
        0: x509.ReasonFlags.unspecified,
        1: x509.ReasonFlags.key_compromise,
        2: x509.ReasonFlags.ca_compromise,
        3: x509.ReasonFlags.affiliation_changed,
        4: x509.ReasonFlags.superseded,
        5: x509.ReasonFlags.cessation_of_operation,
        6: x509.ReasonFlags.certificate_hold,
        8: x509.ReasonFlags.remove_from_crl,
        9: x509.ReasonFlags.privilege_withdrawn,
        10: x509.ReasonFlags.aa_compromise,
    }
    # Create a CRL builder
    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(ca_cert.subject)
    crl_builder = crl_builder.last_update(datetime.datetime.now(datetime.timezone.utc))
    crl_builder = crl_builder.next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))

    for cert in revokeCertsInfo:
        # Create a revoked certificate entry
        revoked_cert_builder = x509.RevokedCertificateBuilder()
        revoked_cert_builder = revoked_cert_builder.serial_number(cert.get("serial_number", None))  # Replace with the actual serial number
        revoked_cert_builder = revoked_cert_builder.revocation_date(cert.get("revocation_date", datetime.datetime.now(datetime.timezone.utc)))
        revoked_cert_builder = revoked_cert_builder.add_extension(
            x509.CRLReason(reason_map.get(cert.get("crl_reason", 0), x509.ReasonFlags.unspecified)),
            critical=False
        )
        # Finalize the revoked certificate
        revoked_cert = revoked_cert_builder.build()
        # Add the revoked certificate to the CRL
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL with the CA private key
    crl = crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Export the CRL to PEM format
    with open(crl_path, "wb") as crl_file:
        crl_file.write(crl.public_bytes(encoding=serialization.Encoding.PEM))


def append_crl(revokeCertsInfo):
    # revokeCertInfo = {
    #     "serial_number": "123456",
    #     "revocation_date" : datetime(),
    #     "crl_reason": 0,
    # }
    
    reason_map = {
        0: x509.ReasonFlags.unspecified,
        1: x509.ReasonFlags.key_compromise,
        2: x509.ReasonFlags.ca_compromise,
        3: x509.ReasonFlags.affiliation_changed,
        4: x509.ReasonFlags.superseded,
        5: x509.ReasonFlags.cessation_of_operation,
        6: x509.ReasonFlags.certificate_hold,
        8: x509.ReasonFlags.remove_from_crl,
        9: x509.ReasonFlags.privilege_withdrawn,
        10: x509.ReasonFlags.aa_compromise,
    }
    # Load the existing CRL from the file
    with open(crl_path, "rb") as crl_file:
        crl_data = crl_file.read()
    
    # Parse the CRL
    crl = x509.load_pem_x509_crl(crl_data)

    crl_builder = x509.CertificateRevocationListBuilder()
    crl_builder = crl_builder.issuer_name(crl.issuer)
    crl_builder = crl_builder.last_update(datetime.datetime.now(datetime.timezone.utc))
    crl_builder = crl_builder.next_update(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30))
    for revoked in crl:
        crl_builder = crl_builder.add_revoked_certificate(revoked)
    
    for cert in revokeCertsInfo:
        # Create a revoked certificate entry
        revoked_cert_builder = x509.RevokedCertificateBuilder()
        revoked_cert_builder = revoked_cert_builder.serial_number(cert.get("serial_number", None))  # Replace with the actual serial number
        revoked_cert_builder = revoked_cert_builder.revocation_date(cert.get("revocation_date", datetime.datetime.now(datetime.timezone.utc)))
        revoked_cert_builder = revoked_cert_builder.add_extension(
            x509.CRLReason(reason_map.get(cert.get("crl_reason", 0), x509.ReasonFlags.unspecified)),
            critical=False
        )
        # Finalize the revoked certificate
        revoked_cert = revoked_cert_builder.build()
        # Add the revoked certificate to the CRL
        crl_builder = crl_builder.add_revoked_certificate(revoked_cert)

    # Sign the CRL with the CA private key
    new_crl = crl_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Export the CRL to PEM format
    with open(crl_path, "wb") as crl_file:
        crl_file.write(new_crl.public_bytes(encoding=serialization.Encoding.PEM))


subject_info = {
    "country_name": "CN",
    "state_or_province_name": "Beijing City",
    "locality_name": "Beijing City",
    "organization_name": "Tsinghua", 
    "common_name": "baron0426@f.eshark.cc", 
    "email_address": "baron0426@f.eshark.cc",
}

# Step 2: Generate CSR and private key for the user
private_key, csr = generate_csr(subject_info)

# Step 3: Issue certificate using CA
signed_cert = issue_cert(csr)

# Save the signed certificate to a file
cert_path = "baron0426_signed_cert.pem"
with open(cert_path, "wb") as cert_file:
    cert_file.write(signed_cert.public_bytes(serialization.Encoding.PEM))

# Optionally, save the user's private key for later use (such as signing messages)
private_key_path = "baron0426_private_key.pem"
with open(private_key_path, "wb") as private_key_file:
    private_key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

print(f"Certificate for baron0426@f.eshark.cc has been signed and saved as {cert_path}")
print(f"Private key has been saved as {private_key_path}")