
## About
A VPN is like a secret tunnel over the internet. Even though your data travels on public networks, it’s wrapped up so no one else can read or change it. In our simple VPN:

1. **Client** and **Server** agree on how to lock (encrypt) the messages.  
2. They use a math trick (Diffie–Hellman) to pick a shared secret key without ever sending it in the clear.  
3. All messages are then scrambled with that key and stamped with a short code (HMAC) so you know they haven’t been interfered with.

---
## Algorithm
### 1) Start and Cipher Negotiation
- **Server** and **Client** each load a list of supported ciphers and key sizes from TOML files.  
- Client connects to the server and sends:
  ```text
  ProposedCiphers:AES:[128,192,256],Blowfish:[112,224,448],DES3:[168]\n
- Server picks the strongest match (e.g. AES-256) and replies: (ChosenCipher:AES,256)
### 2) Key Exchange
- Both sides create a DiffieHellman() object
- Client → Server: DHMKE:<client_public_key>
- Server → Client: DHMKE:<server_public_key>
- Each runs generate_shared_secret() and reads dh.shared_key to get the same secret.
### 3) Derive Key & IV
- Convert the shared secret (hex string) to bytes.
- Key = first key_size/8 bytes (e.g. 32 bytes for AES-256).
- IV = last iv_length bytes (16 bytes for AES).
- Initialize the cipher in CBC mode and an HMAC object with SHA-256.
### 4) Secure Chat Loop
- The client asks you to type a message, adds zeros until its length hits a multiple of 16, locks it with the chosen cipher, makes a small code (HMAC) to prove it’s genuine, and sends both together. The server gets that packet, pulls off the code, checks it (and rejects the message if it fails), unlocks the rest to get the original text, strips away the extra zeros, prints your message, and then—for the demo—sends it back to you spelled backwards.
---
## Usage
- Configure your server_cipher.toml and client_cipher.toml with supported ciphers.
- In one terminal, run the server:
```bash
$python server.py
```
- In another terminal, run the client:
```bash
$python client.py
```
- Follow the prompts to exchange encrypted messages.
- Type \quit at the client to close the connection.
---
## Example
### Server side
```bash
$ python3 server.py
Listening on 127.0.0.1:4600
New client: 127.0.0.1:57106
Negotiating the cipher
We are going to use AES256
Negotiating the key
The key has been established
Received: Hi Tushig
Received: How is your day
Received: See you!
Server shutting down
```
### Client side
```bash
$ python3 client.py
Connected to 127.0.0.1:4600
Negotiating the cipher
We are going to use AES256
Negotiating the key
The key has been established
Enter message (or \quit): Hi Tushig
Server replied: gihsuT iH
Enter message (or \quit): How is your day
Server replied: yad ruoy si woH
Enter message (or \quit): See you!
Server replied: !uoy eeS
Enter message (or \quit): \quit
```
