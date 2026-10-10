# Keys with zero bytes at the edge of the secret

These fixtures cover fixed-length secrets with a zero byte at one end, which a minimal integer encoding drops:

- `ssh_key_p256_leading_zero`: OpenSSH ECDSA P-256 key whose secret starts with `0x00`; its `mpint` is 31 bytes.
- `ssh_key_ed25519_leading_zero`: OpenSSH Ed25519 key whose seed starts with `0x00`.
- `../putty/p256_leading_zero.ppk` and `../putty/ed25519_leading_zero.ppk`: the same two keys converted to PPK v3.
- `../putty/ed25519_v2_short_secret.ppk`: PPK v2 Ed25519 key whose little-endian secret PuTTY wrote as 31 bytes, without its trailing zero byte.

## Tools

- `ssh-keygen` from OpenSSH 9.6p1 (Ubuntu package `openssh-client` 1:9.6p1-3ubuntu13.18).
- `puttygen` 0.81 (Ubuntu package `putty-tools` 0.81-1).
- `puttygen` 0.73 (Ubuntu package `putty-tools` 0.73-2), because PuTTY 0.75 and later always write the Ed25519 secret at full length.
- Python 3.12 to inspect the generated secrets.

## Generation

Each loop regenerates a key until its secret has the wanted shape.
Run the script from an empty directory, then move the PPK files to `../putty`.

```bash
#!/usr/bin/env bash
# Usage: PUTTYGEN=puttygen-0.81 PUTTYGEN_OLD=puttygen-0.73 ./gen.sh
set -euo pipefail

# Exits with 0 when the secret in $1 has the wanted zero byte:
# its first byte is 0x00 (openssh-ecdsa, openssh-ed25519),
# or PuTTY stored it shorter than 32 bytes (ppk-ed25519-short).
is_wanted_key() {
python3 - "$1" "$2" <<'EOF'
import base64, struct, sys

def read_string(buf, off):
    (n,) = struct.unpack(">I", buf[off:off + 4])
    return buf[off + 4:off + 4 + n], off + 4 + n

path, fmt = sys.argv[1], sys.argv[2]
lines = open(path).read().splitlines()

if fmt == "ppk-ed25519-short":
    # PuTTY before 0.75 writes the little-endian secret without its trailing zero bytes.
    start = next(i for i, line in enumerate(lines) if line.startswith("Private-Lines:"))
    count = int(lines[start].split(":")[1])
    secret, _ = read_string(base64.b64decode("".join(lines[start + 1:start + 1 + count])), 0)
    sys.exit(0 if len(secret) < 32 else 1)

blob = base64.b64decode("".join(line for line in lines if not line.startswith("-----")))
off = len(b"openssh-key-v1\0")
for _ in range(3):  # cipher name, KDF name, KDF options
    _, off = read_string(blob, off)
off += 4  # number of keys
_, off = read_string(blob, off)  # public key
private, _ = read_string(blob, off)
_, off = read_string(private, 8)  # key type, after the two check integers

if fmt == "openssh-ed25519":
    _, off = read_string(private, off)  # public key
    secret, _ = read_string(private, off)
    secret = secret[:32]
else:
    _, off = read_string(private, off)  # curve name
    _, off = read_string(private, off)  # public point
    secret, _ = read_string(private, off)  # mpint
    secret = secret.lstrip(b"\0").rjust(32, b"\0")

sys.exit(0 if secret[0] == 0 else 1)
EOF
}

generate_openssh() {
    local type=$1 fmt=$2 out=$3
    shift 3
    while :; do
        rm -f "$out" "$out.pub"
        ssh-keygen -q -t "$type" "$@" -N "" -C "test_leading_zero@picky.com" -f "$out"
        is_wanted_key "$out" "$fmt" && break
    done
    rm -f "$out.pub"
}

generate_openssh ecdsa openssh-ecdsa ssh_key_p256_leading_zero -b 256
generate_openssh ed25519 openssh-ed25519 ssh_key_ed25519_leading_zero

"$PUTTYGEN" ssh_key_p256_leading_zero -O private -o p256_leading_zero.ppk --new-passphrase /dev/null
"$PUTTYGEN" ssh_key_ed25519_leading_zero -O private -o ed25519_leading_zero.ppk --new-passphrase /dev/null

while :; do
    "$PUTTYGEN_OLD" -q -t ed25519 -C "test_leading_zero@picky.com" -o ed25519_v2_short_secret.ppk --new-passphrase /dev/null
    is_wanted_key ed25519_v2_short_secret.ppk ppk-ed25519-short && break
done
```
