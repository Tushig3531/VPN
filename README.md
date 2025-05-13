---
## Table of Contents

- [About](#about)  
- [Diagram](#diagram)  
- [How It Works](#how-it-works)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Usage](#usage)
---

## About
A VPN is like a secret tunnel over the internet. Even though your data travels on public networks, it’s wrapped up so no one else can read or change it. In our simple VPN:

1. **Client** and **Server** agree on how to lock (encrypt) the messages.  
2. They use a math trick (Diffie–Hellman) to pick a shared secret key without ever sending it in the clear.  
3. All messages are then scrambled with that key and stamped with a short code (HMAC) so you know they haven’t been interfered with.

---
