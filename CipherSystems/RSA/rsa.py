import sys 
import os
import secrets
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms.algorithms import algorithm_fast_pow, algorithm_euclid_extended, algorithm_generate_prime, algorithm_comprasion
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta

def generate_padding(length):
    while True:
        padding = secrets.token_bytes(length)
        if all(byte != 0 for byte in padding):
            return b'\x00\x02' + padding + b'\x00'

def generate_keys(length):
    p, q = algorithm_generate_prime(length // 2, 50), algorithm_generate_prime(length // 2, 50)
    N = p * q
    phi_N = (p-1)*(q-1)
    while True:
        e = secrets.randbelow(phi_N - 3) + 3
        if algorithm_euclid_extended(e, phi_N)[0] != 1:
            continue
        
        d = algorithm_comprasion(e,1, phi_N)[0]
        if d > 1/3 * (N ** (1/4)):
            break
        
    scrt_key = {
        "privateExponent": d,
        "prime1": p,
        "prime2": q,
        "exponent1": d % (p - 1),
        "exponent2": d % (q - 1),
        "coefficient": algorithm_comprasion(q, 1, p)[0]
    }

    pub_key = {
        "SubjectPublicKeyInfo": {
            "publicExponent": e,
            "N": N
        },
        "PKCS10CertRequest": 0,
        "Certificate": 0,
        "PKCS7CertChain-PKCS": 0
    }

    password = "P@ssw0rd"  
    save_keys_windows_format(pub_key, scrt_key, password)

    return pub_key, scrt_key

def encrypt(message):
    pub_key = load_public_key_from_pem("CipherSystems/RSA/rsa_keys/pub_key.pem")
    N = pub_key["SubjectPublicKeyInfo"]["N"]
    block_size = (N.bit_length() + 7) // 8
    max_msg_len = block_size - 3 - 8

    encoded = message.encode('utf-8')
    blocks = [encoded[i:i + max_msg_len] for i in range(0, len(encoded), max_msg_len)]
    enc_blocks = []
    for block in blocks:
        pad_length = block_size - 3 - len(block)
        if pad_length < 8:
            raise ValueError("Message too long for RSA block")
            
        padding = generate_padding(pad_length)
        padded_block = padding + block
        int_block = int.from_bytes(padded_block, 'big')
        enc_block = algorithm_fast_pow(int_block, pub_key["SubjectPublicKeyInfo"]["publicExponent"], N)
        enc_blocks.append(enc_block)

    return enc_blocks
    

def decrypt(password, enc_message):
    scrt_key = load_private_key_from_pfx("CipherSystems/RSA/rsa_keys/key_store.pfx", password)
    N = scrt_key["prime1"] * scrt_key["prime2"]
    block_size = (N.bit_length() + 7) // 8
    dec_blocks = []
    for block in enc_message:
        dec_m = algorithm_fast_pow(block, scrt_key["privateExponent"], N)

        dec_block = dec_m.to_bytes(block_size, byteorder='big')
        index = dec_block.find(b'\x00', 2)
        if index == -1:
            raise ValueError("Invalid padding")
        dec_blocks.append(dec_block[index+1:])
    
    return b''.join(dec_blocks).decode('utf-8')

def save_keys_windows_format(pub_key, scrt_key, password, filename="CipherSystems/RSA/rsa_keys/key_store.pfx"): 
    private_numbers = rsa.RSAPrivateNumbers(
        p=scrt_key["prime1"],
        q=scrt_key["prime2"],
        d=scrt_key["privateExponent"],
        dmp1=scrt_key["exponent1"],
        dmq1=scrt_key["exponent2"],
        iqmp=scrt_key["coefficient"],
        public_numbers=rsa.RSAPublicNumbers(
            e=pub_key["SubjectPublicKeyInfo"]["publicExponent"],
            n=pub_key["SubjectPublicKeyInfo"]["N"]
        )
    )
    private_key = private_numbers.private_key()
    public_key = private_key.public_key()

    country = str(input("Enter country name: "))
    region = str(input("Enter state or province name: "))
    org = str(input("Enter organization name: "))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, region),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])

    cert = x509.CertificateBuilder().subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .sign(private_key, hashes.SHA256(), default_backend())

    # export in PKCS#12 (Windows)
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"key",  # container name
        key=private_key,
        cert=cert,
        cas=None,  # extra certs
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    with open(filename, "wb") as f:
        f.write(p12_data)

    with open("CipherSystems/RSA/rsa_keys/pub_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


def load_private_key_from_pfx(filename, password):
    with open(filename, "rb") as f:
        pfx_data = f.read()

    private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
        pfx_data, password.encode(), default_backend()
    )

    private_numbers = private_key.private_numbers()
    
    scrt_key = {
        "privateExponent": private_numbers.d,
        "prime1": private_numbers.p,
        "prime2": private_numbers.q,
        "exponent1": private_numbers.dmp1,
        "exponent2": private_numbers.dmq1,
        "coefficient": private_numbers.iqmp
    }
    return scrt_key

def load_public_key_from_pem(filename):
    with open(filename, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    public_numbers = public_key.public_numbers()
    
    pub_key = {
        "SubjectPublicKeyInfo": {
            "publicExponent": public_numbers.e,
            "N": public_numbers.n
        },
        "PKCS10CertRequest": 0,
        "Certificate": 0,
        "PKCS7CertChain-PKCS": 0
    }
    return pub_key





