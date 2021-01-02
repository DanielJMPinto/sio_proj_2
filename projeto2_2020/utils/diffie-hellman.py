from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def dh_generate_parameters(key_size=2048):
    # Generate some parameters
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    return parameters
####################################################################################################
    
def dh_generate_private_key(parameters):
    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    return private_key
####################################################################################################

def dh_generate_public_key(private_key):
    # Generate public key
    public_key = private_key.public_key()
    return public_key
####################################################################################################

def dh_calculete_common_secret(my_private_key, peer_public_key):
    #calculate the common secret between peer and me
    shared_key = my_private_key.exchange(peer_public_key)
    # Perform key derivation.
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data').derive(shared_key)
    return derived_key
####################################################################################################
