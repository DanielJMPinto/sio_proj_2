import os
import binascii
import random
import PyKCS11
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import ExtensionOID
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization
from cryptography.x509.extensions import CRLDistributionPoints,AuthorityInformationAccess
from cryptography.hazmat.primitives.hashes import SHA1
import requests

# authentication types for server
AUTH_CC = "citizen_card"
AUTH_MEM = "memorized_key"


ACCESS_FILE = "access/users.json"

length_by_cipher = {"ChaCha20": 32, "AES": 32, "TripleDES": 24}


def test_compatibility(cipher, mode):
    """Check if default_backend() suport cipher and mode combination"""

    chiper_obj = cipher_params(cipher, os.urandom(length_by_cipher[cipher]))[0]  #need to be object, not interface, to validate_for_algorithm work
    if chiper_obj.name == "ChaCha20":
        return True
    mode_object = None
    if mode == 'CBC':
        mode_object = modes.CBC(os.urandom(16))
    elif mode == 'GCM':
        mode_object = modes.GCM(os.urandom(16), os.urandom(16))
    else:
        return False

    return default_backend().cipher_supported(chiper_obj, mode_object)


def cipher_params(cipher_algorithm, key):

    algorithm = None
    iv = None
    iv_length = 16  # default value

    nonce = None  # Just used for ChaCha20

    cipher_mode = getattr(algorithms, cipher_algorithm)

    if cipher_mode.name == "ChaCha20":
        nonce = os.urandom(16)
        algorithm = cipher_mode(key, nonce)

    else:
        algorithm = cipher_mode(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)

    return algorithm, iv


def key_derivation(hash_algorithm, length, key):
    upper_hash_alg = hash_algorithm.upper()
    return HKDF(
        algorithm=getattr(hashes, upper_hash_alg)(),
        length=length,
        salt=None,
        info=b"",
        backend=default_backend(),
    ).derive(key)


def encryption(data, key, cipher_algorithm, mode):

    algorithm, iv = cipher_params(cipher_algorithm, key)

    if iv is None:  # For ChaCha20
        iv_length = 16
    else:
        iv_length = len(iv)

    padding_length = (iv_length - (len(data) % iv_length)) % iv_length
    data += (padding_length * "\x00").encode()

    is_cha = False
    if iv is None:  # For ChaCha20
        cipher = Cipher(algorithm, None, backend=default_backend())
        iv = algorithm.nonce
        is_cha = True
    else:
        cipher = Cipher(algorithm,
                        getattr(modes, mode)(iv),
                        backend=default_backend())

    encryptor = cipher.encryptor()

    ct = encryptor.update(data) + encryptor.finalize()
    tag = None
    if mode == "GCM" and not is_cha:
        tag = encryptor.tag

    return ct, padding_length, iv, tag


def decryption(data, key, cipher_algorithm, mode, padding_length, iv, tag):

    cipher_mode = getattr(algorithms, cipher_algorithm)
    if cipher_algorithm != "ChaCha20":
        algorithm = cipher_mode(key)
    else:
        algorithm = cipher_mode(key, iv)

    if cipher_algorithm == "ChaCha20":  # For ChaCha20
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
    else:
        cipher = Cipher(
            algorithm,
            mode=modes.CBC(iv)
            if mode == "CBC" else modes.GCM(iv, tag),  # tentar melhorar isto
            backend=default_backend(),
        )

    decryptor = cipher.decryptor()

    output = decryptor.update(data) + decryptor.finalize()

    if padding_length == 0:
        return output

    return output[:-padding_length]


class ProtoAlgorithm:
    def __init__(self, cipher, mode, synthesis_algorithm):
        self.algorithm = "DH"  # Diffie-Hellman
        self.cipher = cipher
        self.mode = mode
        self.synthesis_algorithm = synthesis_algorithm

    def packing(self):
        return f"{self.algorithm}_{self.cipher}_{self.mode}_{self.synthesis_algorithm}"

    def __str__(self):
        return self.packing()


def unpacking(pack_string):
    splitted_string = pack_string.split("_")
    return (
        splitted_string[0],
        splitted_string[1],
        splitted_string[2],
        splitted_string[3],
    )


def DH_parameters(key_size):
    return dh.generate_parameters(generator=2,
                                  key_size=key_size,
                                  backend=default_backend())


def DH_parametersNumbers(p, g):
    pn = dh.DHParameterNumbers(p, g)
    return pn.parameters(default_backend())


def MAC(key, synthesis_algorithm):
    picked_hash = getattr(hashes, synthesis_algorithm)
    return hmac.HMAC(key, picked_hash(), backend=default_backend())


def skey_generate_otp(root, password, synthesis_algorithm, iterations=10000):
    h = MAC(password, synthesis_algorithm)
    h.update(root)

    result = h.finalize()
    for i in range(iterations):
        result = digest(result, synthesis_algorithm)

    return result


def digest(init, synthesis_algorithm):
    picked_hash = getattr(hashes, synthesis_algorithm)
    digest = hashes.Hash(picked_hash(), backend=default_backend())
    digest.update(init)
    return digest.finalize()


def new_cc_session():
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

def load_cert_from_disk(file_name, return_object=True):
    with open(file_name, 'rb') as file:
        pem_data = file.read()

    if return_object:
        return certificate_object_from_pem(pem_data)
    return pem_data


def load_certificates(path):
    all_files = [f"{path}{n}" for n in os.listdir(path) if ".pem" in n]
    
    certificates = {}
    for fn in all_files:
       cert = load_cert_from_disk(fn)
       certificates[cert.subject.rfc4514_string()] = cert
    
    return certificates


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
        result &= certificate_hasnt_purposes(chain[i], ["digital_signature", "content_commitment", "key_encipherment", "data_encipherment"])

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


# mWLLjqFfm2ArJ8drgABM6cu84ABc
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


def validate_revocation_certificate_chain(chain, error_messages):
    # a failed try to use ocsp validation
    for i in range(1, len(chain)):
        subject = chain[i - 1]
        issuer = chain[i]
        builder = ocsp.OCSPRequestBuilder()
        
        builder = builder.add_certificate(subject, issuer, SHA1())
        req = builder.build()
        data = req.public_bytes(serialization.Encoding.DER)

        for e in subject.extensions:
            
            if isinstance(e.value,AuthorityInformationAccess):
                url = e.value._descriptions[0].access_location.value
                print(url)
                headers = {"Content-Type": "application/ocsp-request"}
                r = requests.post(url, data=data, headers=headers )
                ocsp_resp = ocsp.load_der_ocsp_response(r.content)
                print(ocsp_resp.certificate_status)

                if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                    if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.UNKNOWN:
                        status = validate_revocation_certificate_chain_crl([subject,issuer],error_messages)
                        if not status:
                            return False
                    elif ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                        error_messages.append("One of the certificates is revoked")
                        return False
                else:
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