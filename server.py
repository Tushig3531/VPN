#!/usr/bin/env python3
"""
VPN Sever

@author: Tushig Erdenebulgan
@version: 2025.4
"""

import re
import tomllib
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, gethostname, socket
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Hash import HMAC, SHA256
from diffiehellman.diffiehellman import DiffieHellman
from types import ModuleType





HOST = gethostname()
HOST = "127.0.0.1"
PORT = 4600
TEXT_TO_OBJ = {"AES": AES, "Blowfish": Blowfish, "DES3": DES3}
IV_LEN = {"AES": 16, "Blowfish": 8, "DES3": 8}
# KEY_SIZE=256
# IV_SIZE=16


def load_supported_cipher(path):
    with open(path,"rb") as f:
        data=tomllib.load(f)
    supported={}
    for entry in data.get("supported_cipher",[]):
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

def parse_proposal(msg: str) -> dict[str, list[int]]:
    """Parse client's proposal

    :param msg: message from the client with a proposal (ciphers and key sizes)
    :return: the ciphers and keys as a dictionary
    """
    # TODO: Implement this function
    body=msg.split(':',1)[1]
    pattern=r'([A-Za-z0-9]+):\[(.*?)\]'
    matches=re.findall(pattern,body)
    result:dict[str,list[int]]={}
    for algorithm, keys_str in matches:
        if keys_str:
            parts=keys_str.split(",")
            keys=[]
            for part in parts:
                number=int(part)
                keys.append(number)
        else:
            keys=[]
        result[algorithm]=keys
    return result

def select_cipher(supported: dict, proposed: dict) -> tuple[str, int]:
    """Select a cipher to use

    :param supported: dictionary of ciphers supported by the server
    :param proposed: dictionary of ciphers proposed by the client
    :return: tuple (cipher, key_size) of the common cipher where key_size is the longest supported by both
    :raise: ValueError if there is no (cipher, key_size) combination that both client and server support
    """
    # TODO: Implement this function
    best_algorithm=None
    best_size=-1
    for algorithm, sup_keys in supported.items():
        if algorithm in proposed:
            common=set(sup_keys)&set(proposed[algorithm])
            if common:
                size=max(common)
                if size>best_size:
                    best_size=size
                    best_algorithm=algorithm
    if best_algorithm is None:
        raise ValueError("Could not agree on a cipher")
    return best_algorithm, best_size


def generate_cipher_response(cipher: str, key_size: int) -> str:
    """Generate a response message

    :param cipher: chosen cipher
    :param key_size: chosen key size
    :return: (cipher, key_size) selection as a string
    """
    # TODO: Implement this function
    return f"ChosenCipher:{cipher},{key_size}"


def parse_dhm_request(msg: str) -> int:
    """Parse client's DHM key exchange request

    :param msg: client's DHMKE initial message
    :return: number in the client's message
    """
    # TODO: Implement this function
    _,num=msg.split(":",1)
    return int(num)
    

def get_key_and_iv(
    shared_key: str, cipher_name: str, key_size: int
) -> tuple[ModuleType | None, bytes, bytes]:
    """Get key and IV from the generated shared secret key

    :param shared_key: shared key as computed by `diffiehellman`
    :param cipher_name: negotiated cipher's name
    :param key_size: negotiated key size
    :return: (cipher, key, IV) tuple
    cipher_name must be mapped to a Crypto.Cipher object
    `key` is the *first* `key_size` bytes of the `shared_key`
    DES3 key must be padded to 64 bits with 0
    Length `ivlen` of IV depends on a cipher
    `iv` is the *last* `ivlen` bytes of the shared key
    Both key and IV must be returned as bytes
    """
    # TODO: Implement this function
    raw=shared_key.encode('utf-8')
    kb=key_size//8
    key=raw[:kb]
    iv=raw[-IV_LEN[cipher_name]:]
    cipher_mod=TEXT_TO_OBJ.get(cipher_name,AES)
    return cipher_mod,key,iv
    
    

def generate_dhm_response(public_key: int) -> str:
    """Generate DHM key exchange response

    :param public_key: public portion of the DHMKE
    :return: string according to the specification
    """
    # TODO: Implement this function
    return f"DHMKE:{public_key}"


def read_message(msg_cipher: bytes, crypto: ModuleType) -> tuple[str, str]:
    """Read the incoming encrypted message

    :param msg_cipher: encrypted message from the socket
    :crypto: chosen cipher, must be initialized in the `main`
    :return: (plaintext, hmac) tuple
    """
    # TODO: Implement this function
    tag_bytes=msg_cipher[-64:]
    ciphertext=msg_cipher[:-64]
    tag=tag_bytes.decode('utf-8')
    padded=crypto.decrypt(ciphertext)
    plaintext=padded.rstrip(b'\x00').decode('utf-8')
    return plaintext,tag


def validate_hmac(msg_cipher: bytes, hmac_in: str, hashing: ModuleType) -> bool:
    """Validate HMAC

    :param msg_cipher: encrypted message from the socket
    :param hmac_in: HMAC received from the client
    :param hashing: hashing object, must be initialized in the `main`
    :raise: ValueError is HMAC is invalid
    """
    # TODO: Implement this function
    ctext=msg_cipher[:-len(hmac_in)]
    h=hashing.copy()
    h.update(ctext)
    if h.hexdigest() !=hmac_in:
        raise ValueError("Bad HMAC")
    return True


def main():
    """Main event loop

    See project description for details
    """
    supported=load_supported_cipher("server_cipher.toml")

    with socket(AF_INET, SOCK_STREAM) as serv:
        serv.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serv.bind((HOST, PORT))
        serv.listen()
        print(f"Listening on {HOST}:{PORT}")

        conn, addr=serv.accept()
        print(f"New client: {addr[0]}:{addr[1]}")

        # 1) Cipher negotiation
        print("Negotiating the cipher")
        proposal=recv_line(conn)
        alg,key_size=select_cipher(supported, parse_proposal(proposal))
        conn.sendall((generate_cipher_response(alg, key_size) + "\n").encode("utf-8"))
        print(f"We are going to use {alg}{key_size}")

        print("Negotiating the key")
        dhm = DiffieHellman()
        dhm.generate_public_key()               

        # Receive the client’s public key
        req = recv_line(conn)
        client_pk = parse_dhm_request(req)

        # Send our public key
        server_pk = dhm.public_key
        conn.sendall(f"DHMKE:{server_pk}\n".encode("utf-8"))
        # print(f"Sent DHM response: {server_pk}")

        # Compute the shared secret
        dhm.generate_shared_secret(client_pk)
        shared_key = dhm.shared_key
        cipher_mod, key, iv = get_key_and_iv(shared_key, alg, key_size)
        crypto=cipher_mod.new(key, cipher_mod.MODE_CBC, iv)
        hmac_obj=HMAC.new(key, digestmod=SHA256)
        print("The key has been established")

        # 4) Secure messaging loop
        while True:
            data = conn.recv(4096)
            if not data:
                break
            plaintext, tag = read_message(data, crypto)
            validate_hmac(data, tag, hmac_obj)
            print(f"Received: {plaintext}")
            response = plaintext[::-1].encode("utf-8")
            conn.sendall(response)

    print("Server shutting down")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Bye!")
