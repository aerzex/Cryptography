import sys 
import os
import secrets
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from HashFunctions.SHA2 import sha256_function
from MathAlgorithms.NumberTheoreticAlgorithms.algorithms import algorithm_fast_pow, algorithm_euclid_extended, algorithm_generate_prime, algorithm_comprasion
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta

def padding_pkcs1_v1_5_encode(length): # PKCS 1 v1.5
    while True:
        padding = secrets.token_bytes(length)
        if all(byte != 0 for byte in padding):
            return b'\x00\x02' + padding + b'\x00'

def pkcs1_v1_5_padding_decode(data, block_size):
    dec_block = data.to_bytes(block_size, byteorder='big')
    index = dec_block.find(b'\x00', 2)
    if index == -1 or index < 10:  
        raise ValueError("Invalid PKCS#1 v1.5 padding")
    return dec_block[index+1:]


def mgf1(seed: bytes, length: int, hash_func=sha256_function):
    hash_len = 32
    if length > (hash_len << 32):
        raise ValueError("Mask length too large")
    output = b""
    counter = 0
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += hash_func(seed + c)
        counter += 1
    return output[:length]

def oaep_padding_encode(message: bytes, k: int, label: bytes = b""): # PKCS 1 v2.0
    m_len = len(message)
    hash_len = 32
    if m_len > k - 2 * hash_len - 2:
        raise ValueError(f"Message too long: {m_len} bytes, max {k - 2 * hash_len - 2}")

    l_hash = sha256_function(label)
    ps = b"\x00" * (k - m_len - 2 * hash_len - 2)
    db = l_hash + ps + b"\x01" + message
    
    seed = secrets.token_bytes(hash_len)

    db_mask = mgf1(seed, k - hash_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    
    seed_mask = mgf1(masked_db, hash_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    
    return b"\x00" + masked_seed + masked_db

def oaep_padding_decode(encoded: bytes, k: int, label: bytes = b""):
    hash_len = 32
    
    if len(encoded) != k or encoded[0] != 0:
        raise ValueError("Invalid encoded message")

    masked_seed = encoded[1:1 + hash_len]
    masked_db = encoded[1 + hash_len:]
    
    seed_mask = mgf1(masked_db, hash_len)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - hash_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = sha256_function(label)
    if db[:hash_len] != l_hash:
        raise ValueError("Invalid lHash")
    
    i = hash_len
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 1:
        raise ValueError("Invalid OAEP padding")
    return db[i + 1:]
    

def generate_keys(length, dir_path):
    
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
    save_keys_windows_format(pub_key, scrt_key, password, dir_path="CipherSystems/RSA/rsa_keys/")

    return pub_key, scrt_key

def convert_to_bytes(data):
    if isinstance(data, str):
        return data.encode('utf-8')
    elif isinstance(data, int):
        return data.to_bytes((data.bit_length() + 7) // 8 or 1, 'big')
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in data):
        return bytes(data)
    else:
        raise TypeError("Unsupported data type. Use str, int, bytes, or list of bytes.")

def encrypt(message, padding_type="oaep", filename="CipherSystems/RSA/rsa_keys/pub_key.pem"):
    pub_key = load_public_key_from_pem(filename)
    N = pub_key["SubjectPublicKeyInfo"]["N"]
    block_size = (N.bit_length() + 7) // 8

    if padding_type == "pkcs1_v1_5":
        max_msg_len = block_size - 11
    else:
        max_msg_len = block_size - 2 * 32 - 2

    data_bytes = convert_to_bytes(message)
    blocks = [data_bytes[i:i + max_msg_len] for i in range(0, len(data_bytes), max_msg_len)]
    encrypted_bytes = b""

    for block in blocks:
        if padding_type == "pkcs1_v1_5":
            pad_length = block_size - 3 - len(block)
            if pad_length < 8:
                raise ValueError("Message too long for RSA block")
            padding = padding_pkcs1_v1_5_encode(pad_length)
            padded_block = padding + block
        else:
            padded_block = oaep_padding_encode(block, block_size)

        int_block = int.from_bytes(padded_block, 'big')
        enc_block = algorithm_fast_pow(int_block, pub_key["SubjectPublicKeyInfo"]["publicExponent"], N)
        encrypted_bytes += enc_block.to_bytes(block_size, 'big')

    return encrypted_bytes
    

def decrypt(password, enc_message: bytes, padding_type="oaep", filename="CipherSystems/RSA/rsa_keys/key_store.pfx"):
    scrt_key = load_private_key_from_pfx(filename, password)
    N = scrt_key["prime1"] * scrt_key["prime2"]
    block_size = (N.bit_length() + 7) // 8

    if len(enc_message) % block_size != 0:
        raise ValueError("Invalid encrypted message length")

    dec_blocks = []
    for i in range(0, len(enc_message), block_size):
        block = enc_message[i:i + block_size]
        dec_m = algorithm_fast_pow(int.from_bytes(block, 'big'), scrt_key["privateExponent"], N)
        dec_block = dec_m.to_bytes(block_size, byteorder='big')
        if padding_type == "pkcs1_v1_5":
            dec_block = pkcs1_v1_5_padding_decode(dec_m, block_size)
        else:
            dec_block = oaep_padding_decode(dec_block, block_size)
        dec_blocks.append(dec_block)

    return b''.join(dec_blocks)

def save_keys_windows_format(pub_key, scrt_key, password, dir_path): 
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

    with open(dir_path + "scrt_key.pfx", "wb") as f:
        f.write(p12_data)

    with open(dir_path + "pub_key.pem", "wb") as f:
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





