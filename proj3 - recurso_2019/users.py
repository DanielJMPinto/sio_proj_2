import random
import string
import base64
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import padding


def load_cert(filename):
    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        return cert
    except:
        logger.debug("Not PEM.")
    try:
        with open(filename, "rb") as pem_file:
            pem_data = pem_file.read()
            cert = x509.load_der_x509_certificate(pem_data, default_backend())
        return cert
    except:
        logger.debug("Not DER.")


def encrypt_asymmetric(data):
    secure_server_cert = load_cert("server_cert/secure_server.pem")
    public_key = secure_server_cert.public_key()

    bdata = data.encode('utf-8')
    ciphertext = public_key.encrypt(bdata, 
                                    padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA512()), 
                                            algorithm=hashes.SHA512(),
                                            label=None
                                    )
                )

    cipherpw = base64.b64encode(binascii.hexlify(ciphertext)).decode('utf-8')

    return cipherpw


def randomString(stringLength=16):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase                         #  26
    letters += string.ascii_uppercase                        # +26
    letters += "1234567890,;._-}{\"\'\\|+*()[]&%$#!@€£<>/"   # +38

    #                                          Possibilities -> 90 ^ 16
    return ''.join(random.choice(letters) for i in range(stringLength))


def users(encrypt_pw=False):

    users = {}
    for i in range(3):
            p_index = i if i < len(permissions) else -1

            username = first_names[i].lower() + "_" + last_names[i].lower() + "@ua.pt"
            password = randomString()
            print(username, password)
            
            if encrypt_pw:
                #pass
                enc_pw = encrypt_asymmetric(password)
                password = enc_pw

            users[username] = permissions[p_index], password

    return users

def write_csv(users):
    with open('server_db/users.csv', 'w') as f:
        f.write("Username\tPermissions\tPassword\n")
        for username in users.keys():
            permissions, password = users[username]
            f.write(f"{username}\t{permissions}\t{password}\n")


first_names = ["Fruta", "Goncalo", "Hugo"]
last_names = ["Banana", "Almeida", "Oliveira"]
permissions = ['A1-T0', 'A1-T1']


def main():
    #u = users(False)
    #print(u)
    #write_csv(u)

    users_enc_pw = users(True)
    write_csv(users_enc_pw)


if __name__ == '__main__':
    main()
