#!/usr/bin/env python3
"""
VPN Client

@author: Tushig Erdenebulgan
@version: 2025.4
"""
import tomllib
from socket import AF_INET, SOCK_STREAM, gethostname, socket
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Hash import HMAC, SHA256
from diffiehellman.diffiehellman import DiffieHellman
# from types import ModuleType

HOST = gethostname()
HOST = "127.0.0.1"
PORT = 4600
TEXT_TO_OBJ = {"AES": AES, "Blowfish": Blowfish, "DES3": DES3}
IV_LEN = {"AES": 16, "Blowfish": 8, "DES3": 8}


def load_supported_ciphers(path):
    with open(path,'rb') as f:
        data=tomllib.load(f)
    supported={}
    for entry in data.get("supported_cipher", []):
        supported[entry["name"]]=entry["keys"]
    return supported

def recv_line(sock):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.decode("utf-8").rstrip("\n")

def generate_cipher_proposal(supported: dict[str, list[int]]) -> str:
    """Generate a cipher proposal message

    :param supported: cryptosystems supported by the client
    :return: proposal as a string
    """
    # TODO: Implement this function
    parts=[]
    for algorithm, keys in supported.items():
        string_keys=[]
        for k in keys:
            k_str=str(k)
            string_keys.append(k_str)
        keystream=",".join(string_keys)
        parts.append(f"{algorithm}:[{keystream}]")
    return "ProposedCiphers:"+",".join(parts)


def parse_cipher_selection(msg: str) -> tuple[str, int]:
    """Parse server's response

    :param msg: server's message with the selected cryptosystem
    :return: (cipher_name, key_size) tuple extracted from the message
    """
    # TODO: Implement this function
    _,rest=msg.split(":",1)
    algorithm,size=rest.split(",",1)
    return algorithm, int(size)


def generate_dhm_request(public_key: int) -> str:
    """Generate DHM key exchange request

    :param: client's DHM public key
    :return: string according to the specification
    """
    # TODO: Implement this function
    return f"DHMKE:{public_key}"


def parse_dhm_response(msg: str) -> int:
    """Parse server's DHM key exchange request

    :param msg: server's DHMKE message
    :return: number in the server's message
    """
    # TODO: Implement this function
    _,num=msg.split(":",1)
    return int(num)

def get_key_and_iv(
    shared_key: str, cipher_name: str, key_size: int
) -> tuple[object, bytes, bytes]:
    """Get key and IV from the generated shared secret key

    :param shared_key: shared key as computed by `diffiehellman`
    :param cipher_name: negotiated cipher's name
    :param key_size: negotiated key size
    :return: (cipher, key, IV) tuple
    cipher_name must be mapped to a Crypto.Cipher object
    `key` is the *first* `key_size` bytes of the `shared_key`
    DES key must be padded to 64 bits with 0
    Length `ivlen` of IV depends on a cipher
    `iv` is the *last* `ivlen` bytes of the shared key
    Both key and IV must be returned as bytes
    """
    # TODO: Implement this function
    raw = shared_key.encode("utf-8")
    kb=key_size//8
    key=raw[:kb]
    iv=raw[-IV_LEN[cipher_name]:]
    cls = TEXT_TO_OBJ[cipher_name]
    return cls,key,iv
    
    


def add_padding(message) -> str:
    """Add padding (0x0) to the message to make its length a multiple of 16

    :param message: message to pad
    :return: padded message
    """
    # TODO: Implement this function
    # pad_len=(block_size-len(data)%block_size)%block_size
    pad_len=(16-len(message)%16)%16
    return message+"\x00"*pad_len


def encrypt_message(message: str, crypto, hashing) -> tuple[bytes, str]:
    """
    Encrypt the message

    :param message: plaintext to encrypt
    :param crypto: chosen cipher, must be initialized in the `main`
    :param hashing: hashing object, must be initialized in the `main`
    :return: (ciphertext, hmac) tuple

    1. Pad the message, if necessary
    2. Encrypt using cipher `crypto`
    3. Compute HMAC using `hashing`
    """
    # TODO: Implement this function
    # plain=message.encode("utf-8")
    # padded=add_padding(plain,crypto.block_size)
    # ciphertext=crypto.encrypt(padded)
    # tag=HMAC.new(hashing,ciphertext,digestmod=SHA256).hexdigest()
    # return ciphertext,tag
    padded = add_padding(message)
    plaintext = padded.encode("utf-8")
    ciphertext=crypto.encrypt(plaintext)
    h=hashing.copy()
    h.update(ciphertext)
    tag=h.hexdigest()
    return ciphertext,tag

def main():
    """Main event loop

    See project description for details
    """
    supported = load_supported_ciphers("client_cipher.toml")
    with socket(AF_INET, SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}")

        # 1) Cipher negotiation
        print("Negotiating the cipher")
        client.sendall((generate_cipher_proposal(supported) + "\n").encode("utf-8"))
        selection=recv_line(client)
        alg, key_size=parse_cipher_selection(selection)
        print(f"We are going to use {alg}{key_size}")

        # Receive DH params
        print("Negotiating the key")
        dh = DiffieHellman()                       
        dh.generate_public_key()
        client_pub = dh.public_key

        # Send our public key
        client.sendall((generate_dhm_request(client_pub) + "\n").encode("utf-8"))
        # print(f"RAW DHM request: {client_pub}")

        # Receive the server’s public key
        resp = recv_line(client)
        server_pk = parse_dhm_response(resp)
        # print(f"RAW DHM response: {server_pk}")

        # Compute the shared secret
        dh.generate_shared_secret(server_pk)
        shared_key = dh.shared_key
        cls, key, iv = get_key_and_iv(shared_key, alg, key_size)
        crypto=cls.new(key, cls.MODE_CBC, iv)
        hmac_obj=HMAC.new(key, digestmod=SHA256)
        print("The key has been established")


        # 4)Secure messaging loop
        while True:
            msg=input("Enter message (or \\quit): ")
            if msg=="\\quit":
                break
            ciphertext, tag=encrypt_message(msg, crypto, hmac_obj)
            client.sendall(ciphertext+tag.encode("utf-8"))
            reply = client.recv(4096).decode("utf-8")
            print("Server replied:",reply)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Bye!")
