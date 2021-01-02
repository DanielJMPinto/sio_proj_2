import os
import PyKCS11
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import CRLDistributionPoints
import requests

def cc_session():
    try:
        lib = '/usr/local/lib/libpteidpkcs11.so'
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(lib)
        slots = pkcs11.getSlotList()
        slot = slots[0]

        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]

        return True, pkcs11.openSession(slot)
    except Exception as e:
        return False, e


def certificate_cc(session):
    return bytes(session.findObjects([(PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')])[0].to_dict()['CKA_VALUE'])


def certificate_object(certificate):
    return x509.load_der_x509_certificate(
        certificate,
        default_backend()
    )


def sign_nonce_cc(session, nonce):
    mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
    private_key = session.findObjects([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')]
    )[0]
    return bytes(session.sign(private_key, nonce, mechanism))


def verify_signature(certificate, signature, nonce):
    try:
        issuer_public_key = certificate.public_key()
        issuer_public_key.verify(
            signature,
            nonce,
            padding.PKCS1v15(),
            hashes.SHA1(),
        )
    except InvalidSignature:
        return False

    return True


def certificate_object_from_pem(pem_data):
    return x509.load_pem_x509_certificate(pem_data, default_backend())

def load_cert_from_disk(file_name):
    with open(file_name, 'rb') as file:
        pem_data = file.read()

    return pem_data


def construct_certificate_chain(chain, cert, certificates):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in certificates:
        return True

    if issuer in certificates:
        return construct_certificate_chain(chain, certificates[issuer], certificates)
    
    return False


def validate_certificate_chain(chain):
    error_messages = []
    try:
        # taking advantage of the python's lazy evaluation, we could define the validation order just with this instruction
        return (validate_purpose_certificate_chain(chain,error_messages)
                and validate_validity_certificate_chain(chain, error_messages) 
                and validate_revocation_certificate_chain_crl(chain,error_messages) 
                and validate_signatures_certificate_chain(chain, error_messages)), error_messages
    except Exception as e:
        error_messages.append("Some error occurred while verifying certificate chain")
        return False, error_messages


def validate_purpose_certificate_chain(chain, error_messages):
    result = certificate_hasnt_purposes(chain[0], ["key_cert_sign", "crl_sign"])
    for i in range(1, len(chain)):
        
        if not result:
            
            error_messages.append("The purpose of at least one chain certificate is wrong")
            return result
       
        result = certificate_hasnt_purposes(chain[i], ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment"])

    if not result:
        error_messages.append("The purpose of at least one chain certificate is wrong")
    return result


def validate_validity_certificate_chain(chain, error_messages):
    for cert in chain:
        dates = (cert.not_valid_before.timestamp(), cert.not_valid_after.timestamp())

        if datetime.now().timestamp() < dates[0] or datetime.now().timestamp() > dates[1]:
            error_messages.append("One of the chain certificates isn't valid")
            return False
    return True


def is_certificate_revoked(serial_number, crl_url):
    r = requests.get(crl_url)
    try:
        crl = x509.load_der_x509_crl(r.content, default_backend())
    except ValueError as e:
        crl = x509.load_pem_x509_crl(r.content, default_backend())
    return crl.get_revoked_certificate_by_serial_number(serial_number) is not None


def validate_revocation_certificate_chain_crl(chain, error_messages):
    for i in range(1, len(chain)):
        subject = chain[i - 1]
        issuer = chain[i]
        for e in issuer.extensions:
            if isinstance(e.value, CRLDistributionPoints):
                crl_url = e.value._distribution_points[0].full_name[0].value
                if is_certificate_revoked(subject.serial_number,crl_url):
                    error_messages.append("One of the certificates is revoked")
                    return False
    return True



def validate_signatures_certificate_chain(chain, error_messages):
    for i in range(1, len(chain)):
        try:
            subject = chain[i - 1]
            issuer = chain[i]
            issuer_public_key = issuer.public_key()
            issuer_public_key.verify(
                subject.signature,
                subject.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subject.signature_hash_algorithm,
            )
        except InvalidSignature:
            error_messages.append("One of the certificates isn't signed by its issuer")
            return False
    return True


def certificate_hasnt_purposes(certificate, purposes):
    result = True
    for purpose in purposes:
        result &= not getattr(certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value, purpose)
    return result

def load_private_key_file(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def sign_with_pk(pk, nonce):
    return pk.sign(nonce, padding.PKCS1v15(), hashes.SHA1())