# ECC Secure Communication on Two Raspberry Pis

This repository contains the runnable presentation implementation of a secure
Pi-to-Pi channel. It is not an in-process simulation: two Raspberry Pis
communicate over a TCP connection, verify a signed application artifact before
starting, mutually authenticate their device identities, derive a session key,
and exchange ASCON-128a encrypted messages.

## What the presentation proves

1. **Secure boot check:** the launcher hashes the deployed artifact and verifies
   an ECDSA signature from the manufacturer key. A modified artifact stops the
   node *before it opens a socket*.
2. **Device authentication:** each Pi proves possession of its provisioned
   ECDSA private key. The peer public key is pinned during provisioning.
3. **Key establishment:** ephemeral P-256 ECDH and HKDF-SHA256 derive the same
   128-bit session key without sending that key over the network.
4. **Confidentiality and integrity:** ASCON-128a encrypts each message. The
   packet authenticates its sender, sequence number, and protocol version as
   associated data.
5. **Freshness:** sequence numbers reject replayed or out-of-order packets.
   The `--tamper` presentation option demonstrates authentication failure.
6. **Secure shutdown:** the session key and ECDH state are cleared when the
   session ends.

ASCON-128a is implemented in this repository in pure Python
(`ECC_Integration/ASCON_Encryption.py`), so the project has no lightweight-crypto
dependency to install. It is validated against the official ascon-c v1.2
known-answer vectors (see [Tests](#tests)).

This is a strong educational/demo deployment, not a replacement for a
hardware-rooted secure bootloader or a production PKI. Keep the manufacturer
signing key offline. Read [Limitations](#limitations) before presenting this as
more than it is.

## Files used on the Pis

| File | Purpose |
| --- | --- |
| `secure_launcher.py` | Verifies the signed artifact, then executes it |
| `pi_node.py` | The **signed artifact**: node, handshake, and wire protocol |
| `provision.py` | One-time offline provisioning tool (not copied to the Pis) |
| `ECC_Integration/ECC_Core.py` | P-256 ECDH and HKDF-SHA256 |
| `ECC_Integration/ASCON_Encryption.py` | ASCON-128a AEAD (pure Python, no dependency) |
| `ECC_Integration/Secure_Boot.py` | Artifact hash/signature verification |
| `requirements.txt` | Python dependencies |
| `Validation/Test_*.py` | Regression tests (not needed at runtime) |

`ECC_Integration/ECDSA_Auth.py` is used only by the tests, not by the node.

## 1. Install on both Raspberry Pis

Use Raspberry Pi OS with Python 3.9 or newer (Bookworm ships 3.11). Connect both
Pis to the same trusted LAN and note the server Pi's address.

Clone the repository on each Pi, or copy the provisioned node directory as
described in section 3 — either way the deployment directory must contain
`ECC_Integration/`, because `pi_node.py` imports it.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run the regression tests on one machine before moving to hardware:

```bash
python -m unittest discover -s Validation -p 'Test_*.py'
```

This works from any working directory.

## 2. Provision the two nodes offline

Run this on a development computer, not on either Pi. Use the exact artifact
that will be copied to both Pis. For the presentation, the runnable node is
the artifact:

```bash
python provision.py --firmware pi_node.py --output deployment
```

This creates `deployment/pi-a` and `deployment/pi-b`. **Each directory is a
complete, self-contained deployment**:

```
deployment/pi-a/
  secure_launcher.py        trusted bootstrap
  pi_node.py                the SIGNED artifact — this is what runs
  pi_node.py.sig
  node.json                 node identity and peer configuration
  identity_private.pem      this node's ECDSA identity key (mode 0600)
  peer_identity_public.pem  the other node's pinned public key
  manufacturer_public.pem   manufacturer trust anchor
  ECC_Integration/          the package the artifact imports
  requirements.txt
```

Without `--manufacturer-key`, a **new** manufacturer key is generated on every
run and its private half is deleted as soon as the artifact is signed. Nothing
from that run can re-sign a modified artifact afterwards. If you want a stable
trust anchor across runs, keep a key offline and pass it explicitly:

```bash
python provision.py --firmware pi_node.py --output deployment \
  --manufacturer-key ~/offline/manufacturer_private.pem
```

Do not commit `deployment/`.

## 3. Copy each node to its own Pi

**Copy only the directory that belongs to that Pi.** Sending both directories
to both devices would put the peer's private identity key on the other device
and destroy the mutual-authentication property this project is built on.

`scp` does not create the destination directory, so create it first:

```bash
ssh pi-a.local 'mkdir -p ~/ecc-secure-node'
ssh pi-b.local 'mkdir -p ~/ecc-secure-node'

scp -r deployment/pi-a/. pi-a.local:~/ecc-secure-node/
scp -r deployment/pi-b/. pi-b.local:~/ecc-secure-node/
```

The trailing `/.` copies the *contents* of the node directory into
`~/ecc-secure-node/`, which is what makes `ECC_Integration` importable when the
launcher runs.

Then create the virtual environment on each Pi, in the deployment directory:

```bash
ssh pi-a.local 'cd ~/ecc-secure-node && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt'
ssh pi-b.local 'cd ~/ecc-secure-node && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt'
```

If the Pi's firewall blocks inbound connections, allow TCP 8765 (the default
port) or pass a different `--port`.

## 4. Run the real Pi-to-Pi demonstration

The server serves **exactly one connection** and then exits. Start a fresh
server for every run.

On **Raspberry Pi B**, start the server:

```bash
cd ~/ecc-secure-node
. .venv/bin/activate
python secure_launcher.py \
  --config ~/ecc-secure-node \
  --role server \
  --host 0.0.0.0 \
  --port 8765 \
  --reply "Pi B received and authenticated the encrypted message"
```

On **Raspberry Pi A**, connect to Pi B:

```bash
cd ~/ecc-secure-node
. .venv/bin/activate
python secure_launcher.py \
  --config ~/ecc-secure-node \
  --role client \
  --host <PI_B_IP_ADDRESS> \
  --port 8765 \
  --message "Pi A: confidential sensor payload"
```

Expected evidence on the terminals:

- `secure_boot` with `PASS`, the artifact name, and its SHA-256;
- `secure_channel` with `ESTABLISHED` and `ECDH + HKDF-SHA256 + ASCON-128a`;
- Pi B prints the plaintext only after authenticating and decrypting the packet;
- Pi A prints the authenticated reply.

The wire carries JSON framing only for transport. The `nonce`, ciphertext,
tag, sender, and sequence fields are transmitted; the plaintext and session
key are not.

## 5. Show tamper detection

Start Pi B as above, then run Pi A with `--tamper`:

```bash
python secure_launcher.py \
  --config ~/ecc-secure-node \
  --role client \
  --host <PI_B_IP_ADDRESS> \
  --port 8765 \
  --message "This packet will be rejected" \
  --tamper
```

Pi B rejects the packet with an ASCON integrity error and never prints a
plaintext. Both processes exit non-zero: the server reports the integrity
failure, and the client reports that the peer rejected the packet. This is the
live proof that changing ciphertext in transit is detected. **Start a fresh
server for the normal run afterward**, because the server serves one connection.

## 6. Show that a modified artifact does not start

Flip a byte in one node's artifact and try to launch it:

```bash
printf '#' >> ~/ecc-secure-node/pi_node.py
python secure_launcher.py --config ~/ecc-secure-node --role client \
  --host <PI_B_IP_ADDRESS> --port 8765
```

The launcher prints `{"event": "secure_boot", "status": "FAIL", ...}` on stderr
and exits non-zero **without opening a socket**. Restore the artifact from
`deployment/` afterwards.

## Protocol details

- Protocol version 2.
- P-256 ECDH creates an ephemeral shared secret for every connection.
- HKDF-SHA256 uses a hash of both signed handshake messages as its salt,
  binding the session key to this exact peer exchange.
- ECDSA signatures authenticate each handshake message against the pinned
  peer identity key. Both directions are authenticated, so the exchange is
  mutually authenticated; there is no separate challenge round trip.
- ASCON-128a uses a 16-byte key, nonce, and authentication tag.
- A canonical packet header (`version`, `type`, `sender`, `sequence`) is
  authenticated as ASCON associated data.
- Each direction starts at sequence `1`; any duplicate or skipped sequence is
  rejected. After any failed decryption the session is terminated rather than
  continuing with desynchronized state.
- Malformed, oversized, or hostile input is rejected with a clean JSON error;
  it never produces a traceback.
- TCP is used only as a transport. It does not provide the security claims.

## Command-line reference

`secure_launcher.py` consumes `--config` and `--manufacturer-public-key` and
forwards everything else to the artifact:

| Option | Meaning |
| --- | --- |
| `--config DIR` | Provisioned node directory (required) |
| `--manufacturer-public-key PEM` | Trust anchor read from **outside** the node directory; defaults to `<config>/manufacturer_public.pem` |
| `--role {server,client}` | Node role (required) |
| `--host ADDR` | Bind address (server) or peer address (client) (required) |
| `--port N` | TCP port, default `8765` |
| `--timeout SECONDS` | Connect, accept, and read timeout, default `15`. Bounds `accept()`, so a server with no client exits instead of hanging |
| `--message TEXT` | Client payload |
| `--reply TEXT` | Server reply |
| `--tamper` | Flip one ciphertext bit before sending, to demonstrate rejection |

## Tests

```bash
python -m unittest discover -s Validation -p 'Test_*.py'
```

`Validation/Test_ASCON.py` checks the pure-Python ASCON-128a against the official
ascon-c v1.2 known-answer vectors (`LWC_AEAD_KAT_128_128.txt`, all 1089 vectors
verified in both directions) plus round-trip, tamper, and input-validation
cases. `Validation/Test_Integration.py` provisions a throwaway pair and runs a
real client and server over a loopback socket, covering the normal exchange, the
`--tamper` rejection, and refusal to start on a modified artifact.

## Limitations

Be explicit about these when presenting the work.

- **The launcher is the root of trust, and it is not verified.** Whatever checks
  the signed artifact must itself already be trusted. Anyone who can rewrite
  `secure_launcher.py`, the Python interpreter, or the `cryptography` package
  defeats the check entirely. There is no TPM, no measured boot, and no
  hardware key store.
- **The trust anchor sits next to the artifact by default.** An attacker with
  write access to the node directory can replace `manufacturer_public.pem` and
  re-sign a modified artifact. Pass `--manufacturer-public-key` to keep the
  anchor somewhere the node cannot write, and treat that as the real
  configuration.
- **The secure boot check is application-level.** It runs before the Python
  process opens its network socket. It does not replace Raspberry Pi firmware,
  U-Boot, or a hardware-backed boot chain.
- **A provisioned manufacturer key is throwaway by default.** Without
  `--manufacturer-key`, each provisioning run mints a new key and discards the
  private half, so the anchor is not stable across runs.
- **The server is single-shot.** It serves one connection and exits; there is no
  reconnect, retry, or rotation. Restart it for each demonstration.
- **No key rotation or revocation.** Device identities are static once
  provisioned.

For a production deployment, keep the manufacturer signing key in an HSM or
secure workstation, pin the trust anchor outside the writable node directory,
use OS service hardening, rotate and revoke device identities, and add a
hardware-rooted boot chain.
