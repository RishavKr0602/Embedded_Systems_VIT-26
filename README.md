# ECC Secure Communication on Two Raspberry Pis

This repository contains the runnable presentation implementation of a secure
Pi-to-Pi channel. It is not an in-process simulation: two Raspberry Pis
communicate over a TCP connection, verify a signed application artifact before
starting, mutually authenticate their device identities, derive a session key,
and exchange ASCON-128a encrypted messages.

## What the presentation proves

1. **Secure boot check:** each Pi hashes the deployed artifact and verifies an
   ECDSA signature from the manufacturer key. A modified artifact stops the
   node before networking.
2. **Device authentication:** each Pi proves possession of its provisioned
   ECDSA private key. The peer public key is pinned during provisioning.
3. **Key establishment:** ephemeral P-256 ECDH and HKDF-SHA256 derive the same
   128-bit session key without sending that key over the network.
4. **Confidentiality and integrity:** ASCON-128a encrypts each message. The
   packet authenticates its sender, sequence number, and protocol version as
   associated data.
5. **Freshness:** sequence numbers reject replayed or out-of-order packets.
   The `--tamper` presentation option demonstrates authentication failure.

This is a strong educational/demo deployment, not a replacement for a
hardware-rooted secure bootloader or a production PKI. Keep the manufacturer
signing key offline.

## Files used on the Pis

| File | Purpose |
| --- | --- |
| `pi_node.py` | Long-running server/client node and wire protocol |
| `provision.py` | One-time offline provisioning tool |
| `ECC_Integration/ECC_Core.py` | P-256 ECDH and HKDF-SHA256 |
| `ECC_Integration/ASCON_Encryption.py` | ASCON-128a AEAD |
| `ECC_Integration/Secure_Boot.py` | Artifact hash/signature verification |
| `requirements.txt` | Python dependencies |
| `Validation/Test_Crypto.py` | Local crypto regression tests |

The old in-memory full-pipeline runner, generated logs, fake firmware, and
ESP32/Arduino experiments are not part of the deployment path.

## 1. Install on both Raspberry Pis

Use Raspberry Pi OS with Python 3.10 or newer. Connect both Pis to the same
trusted LAN and note the server Pi's address.

```bash
git clone <repository-url>
cd Embedded_Systems_VIT-26
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the regression tests on one machine before moving to hardware:

```bash
python -m unittest discover -s Validation -p 'Test_*.py'
```

## 2. Provision the two nodes offline

Run this on a development computer, not on either Pi. Use the exact artifact
that will be copied to both Pis. For the presentation, the runnable node is
the artifact:

```bash
python provision.py --firmware pi_node.py --output deployment
```

This creates `deployment/pi-a` and `deployment/pi-b`, each containing:

- a unique ECDSA identity private key;
- the other node's pinned public identity key;
- the manufacturer public key;
- the signed artifact and signature;
- `node.json` with the node's identity and peer configuration.

The manufacturer private key is deleted from `deployment` after signing. Back
up the original offline signing key if this will be used beyond the
presentation. Do not commit `deployment/`.

Copy the directories to the Pis, for example:

```bash
scp -r deployment/pi-a pi-a.local:~/ecc-secure-node/
scp -r deployment/pi-b pi-b.local:~/ecc-secure-node/
scp pi_node.py pi-a.local:~/ecc-secure-node/
scp pi_node.py pi-b.local:~/ecc-secure-node/
```

The copied `pi_node.py` is only the launcher; the signed artifact in each node
directory is what secure boot verifies. If the artifact changes, provision
again and copy the newly generated node directories.

## 3. Run the real Pi-to-Pi demonstration

On **Raspberry Pi B**, start the server. Replace the address and port if
needed:

```bash
cd ~/ecc-secure-node
. .venv/bin/activate
python ~/ecc-secure-node/pi_node.py \
  --config ~/ecc-secure-node/pi-b \
  --role server \
  --host 0.0.0.0 \
  --port 8765 \
  --reply "Pi B received and authenticated the encrypted message"
```

On **Raspberry Pi A**, connect to Pi B:

```bash
cd ~/ecc-secure-node
. .venv/bin/activate
python ~/ecc-secure-node/pi_node.py \
  --config ~/ecc-secure-node/pi-a \
  --role client \
  --host <PI_B_IP_ADDRESS> \
  --port 8765 \
  --message "Pi A: confidential sensor payload"
```

Expected evidence on the terminals:

- `secure_boot` with `PASS` and the artifact SHA-256;
- `secure_channel` with `ESTABLISHED` and `ECDH + HKDF-SHA256 + ASCON-128a`;
- Pi B prints the plaintext only after authenticating and decrypting the packet;
- Pi A prints the authenticated reply.

The wire carries JSON framing only for transport. The `nonce`, ciphertext,
tag, sender, and sequence fields are transmitted; the plaintext and session
key are not.

## 4. Show tamper detection

Start Pi B as above, then run Pi A with `--tamper`:

```bash
python ~/ecc-secure-node/pi_node.py \
  --config ~/ecc-secure-node/pi-a \
  --role client \
  --host <PI_B_IP_ADDRESS> \
  --port 8765 \
  --message "This packet will be rejected" \
  --tamper
```

Pi B must reject the packet with an ASCON integrity error and must not print a
plaintext. This is the live proof that changing ciphertext in transit is
detected. Start a fresh server for the normal run afterward.

## Protocol details

- P-256 ECDH creates an ephemeral shared secret for every connection.
- HKDF-SHA256 uses a hash of both signed handshake messages as its salt,
  binding the session key to this exact peer exchange.
- ECDSA signatures authenticate each handshake message against the pinned
  peer identity key.
- ASCON-128a uses a 16-byte key, nonce, and authentication tag.
- A canonical packet header (`version`, `type`, `sender`, `sequence`) is
  authenticated as ASCON associated data.
- Each direction starts at sequence `1`; any duplicate or skipped sequence is
  rejected.
- TCP is used only as a transport. It does not provide the security claims.

## Limitations

The secure boot check is application-level verification performed before the
Python process opens its network socket. It does not replace Raspberry Pi
firmware, U-Boot, TPM, or a hardware-backed key store. For a production
deployment, keep the manufacturer signing key in an HSM/secure workstation,
use OS service hardening, rotate/revoke device identities, and add a
hardware-rooted boot chain.
