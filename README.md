Cryptographic Protocols in This Project
Overview

This project implements a secure Bulletin Board System (BBS), emphasizing cryptographic security and ensuring the confidentiality, integrity, and authenticity of data exchanged between clients and the server. This document provides an overview of the cryptographic protocols used, highlighting the design decisions and their implementation.
Key Cryptographic Components
1. Session Establishment Protocol

The session establishment protocol is based on the authenticated Station-to-Station protocol. It ensures secure key exchange and mutual authentication between the client and the server.
Steps:

    Diffie-Hellman Key Exchange:

        The client generates a random value, computes the corresponding exponentiation, and sends it to the server.

        The server generates its random value, computes its exponentiation, and derives the shared secret.

    Authentication:

        Both client and server exchange signatures tied to the specific session keys, ensuring no attacker can impersonate either party.

    Session Keys:

        The shared secret is hashed using SHA-512, dividing the result into two keys:

            Session Key: For encrypting messages.

            HMAC Key: For ensuring message integrity.

Security Properties:

    Mutual Authentication

    Perfect Forward Secrecy (PFS)

    Protection against replay attacks via session counters.

2. Session Message Protocol

Messages exchanged during an established session are protected using:
Encryption:

    Algorithm: AES in CBC mode.

    Purpose: Provides confidentiality for message payloads.

Integrity:

    Algorithm: HMAC with SHA-512.

    Purpose: Ensures message integrity and guards against tampering.

Structure:

Each message includes:

    IV (Initialization Vector)

    Ciphertext

    HMAC

This structure ensures that the receiver can verify the authenticity and integrity of the message before decrypting its content.
3. Login Phase Protocol

The login process ensures secure authentication without exposing sensitive credentials.
Workflow:

    The client sends the username.

    The password is hashed using SHA-512 and sent as part of a secure session message.

    The server validates the hashed password against stored credentials.

Security Features:

    Passwords are never transmitted in plain text.

    Replay protection via session counters.

4. Registration Phase Protocol

The registration process introduces a challenge-response mechanism to validate user email addresses and secure account creation.
Workflow:

    The server generates a time-based challenge using TOTP (Time-based One-Time Passwords) compliant with RFC 6238.

    The client responds with the correct challenge value, proving control over the provided email address.

Security Features:

    Challenges are unique and time-bound.

    Ensures that accounts can only be registered by verified users.

Security Design Considerations

    No Clear Text Storage or Transmission: Sensitive data like passwords are always hashed and transmitted securely.

    Thread Safety: File access and critical operations are protected by locks to ensure consistency in concurrent environments.

    Replay and Malleability Protections:

        Use of session counters.

        HMAC validation.

    Implementation Constraints:

        The project utilizes OpenSSL for cryptographic operations but avoids using pre-built TLS APIs to demonstrate in-depth protocol implementation.

Conclusion

This project leverages state-of-the-art cryptographic protocols to ensure secure communication and data protection. By implementing robust session establishment, message handling, and user authentication protocols, it provides a reliable foundation for a secure distributed service.

