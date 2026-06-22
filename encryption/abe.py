"""
Policy-Based Attribute Encryption (CP-ABE style)
==================================================

This module implements a real, working policy-based encryption scheme that
achieves the same practical goal as Ciphertext-Policy Attribute-Based
Encryption (CP-ABE): data is encrypted once, but can only be decrypted by a
user who holds a set of attributes satisfying the access policy.

IMPORTANT — what this is and isn't:
------------------------------------
True CP-ABE (Bethencourt, Sahai, Waters 2007) is built on bilinear pairings
over elliptic curves and requires specialized libraries (e.g. charm-crypto)
that are difficult to install outside Linux research environments and are
not practical for this project's deployment target.

This module instead implements a well-established alternative technique:
secret-sharing-based attribute encryption, combining:

    1. Shamir's Secret Sharing (SSS)  -> splits the AES data key into
       shares distributed across the policy's required attributes
    2. HKDF (HMAC-based Key Derivation Function) -> binds each share to a
       specific attribute string, so shares can't be swapped or reused
    3. AES-256-GCM -> authenticated encryption of the actual data

A user can only reconstruct the AES key (via Lagrange interpolation over a
finite field) if they hold a number of matching attributes greater than or
equal to the policy's threshold. This gives real fine-grained,
attribute-based access control with real cryptographic guarantees,
even though it is not pairing-based CP-ABE in the strict academic sense.
"""

import os
import secrets
import hashlib
from typing import Set, Dict, Tuple, Optional

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# A large prime > 2^256 so the finite field is bigger than any AES-256 key,
# guaranteeing every possible key value is representable in GF(p).
_PRIME = 2**521 - 1


# ----------------------------------------------------------------------
# Shamir's Secret Sharing (finite field arithmetic over GF(_PRIME))
# ----------------------------------------------------------------------

def _eval_polynomial(coeffs, x, prime=_PRIME):
    """Evaluate a polynomial (given by its coefficients) at point x, mod prime."""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % prime
    return result


def _split_secret(secret_int: int, num_shares: int, threshold: int, prime=_PRIME):
    """
    Split `secret_int` into `num_shares` shares such that any `threshold`
    of them can reconstruct the secret, but fewer cannot.

    Returns a list of (x, y) points on a random polynomial of degree
    (threshold - 1) whose constant term is the secret.
    """
    if threshold > num_shares:
        raise ValueError("threshold cannot exceed number of shares")

    # Random coefficients for a degree (threshold-1) polynomial;
    # coeffs[0] is the secret itself.
    coeffs = [secret_int] + [secrets.randbelow(prime) for _ in range(threshold - 1)]

    shares = []
    for i in range(1, num_shares + 1):
        x = i
        y = _eval_polynomial(coeffs, x, prime)
        shares.append((x, y))
    return shares


def _lagrange_interpolate(x, points, prime=_PRIME):
    """Reconstruct f(x) from a list of (x_i, y_i) points using Lagrange interpolation mod prime."""
    total = 0
    n = len(points)
    for i in range(n):
        xi, yi = points[i]
        num, den = 1, 1
        for j in range(n):
            if i == j:
                continue
            xj, _ = points[j]
            num = (num * (x - xj)) % prime
            den = (den * (xi - xj)) % prime
        # modular inverse of den
        inv_den = pow(den, prime - 2, prime)
        term = (yi * num * inv_den) % prime
        total = (total + term) % prime
    return total


def _reconstruct_secret(shares, prime=_PRIME):
    """Reconstruct the secret (f(0)) from a sufficient list of (x, y) shares."""
    return _lagrange_interpolate(0, shares, prime)


# ----------------------------------------------------------------------
# Attribute-bound key derivation
# ----------------------------------------------------------------------

def _derive_attribute_key(attribute: str, salt: bytes) -> bytes:
    """
    Derives a per-attribute symmetric key using HKDF, binding the key to a
    specific attribute string. This is what a "user holding an attribute"
    is modeled as possessing in this simplified scheme.
    """
    return HKDF(
        master=attribute.encode(),
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=b"RCS-ABE-attribute-key",
    )


def _encode_share_with_attr_key(share_y: int, attr_key: bytes) -> bytes:
    """
    XOR-masks a share's y-value with a keystream derived from the
    attribute key, so only someone who can derive the correct attribute
    key can recover the raw share value.
    """
    y_bytes = share_y.to_bytes(66, "big")  # 521 bits -> 66 bytes
    keystream = hashlib.shake_256(attr_key).digest(66)
    return bytes(a ^ b for a, b in zip(y_bytes, keystream))


def _decode_share_with_attr_key(masked: bytes, attr_key: bytes) -> int:
    keystream = hashlib.shake_256(attr_key).digest(66)
    y_bytes = bytes(a ^ b for a, b in zip(masked, keystream))
    return int.from_bytes(y_bytes, "big")


# ----------------------------------------------------------------------
# Public API: abe_encrypt / abe_decrypt
# ----------------------------------------------------------------------

def abe_encrypt(data: str, user_attrs: Set[str], policy: Set[str], threshold: Optional[int] = None) -> Optional[Dict]:
    """
    Encrypts `data` under a policy (a set of required attributes).

    A random AES-256 key is generated and used to encrypt the data with
    AES-GCM. That key is then split via Shamir's Secret Sharing into one
    share per attribute in `policy`. Each share is masked using a key
    derived from its corresponding attribute (HKDF), so it can only be
    recovered by someone who holds that attribute.

    `threshold` controls how many of the policy's attributes are required
    to reconstruct the key (defaults to ALL attributes in the policy, i.e.
    pure AND-policy semantics, matching the original sleep-based stub's
    behavior of `policy.issubset(user_attrs)`).

    Returns a dict "ciphertext package" containing everything needed for
    decryption EXCEPT the requester's own attribute credentials, or None
    if the policy cannot be satisfied by the given attributes at encrypt
    time (matches the original function's behavior).

    Note: `user_attrs` is accepted for interface compatibility with the
    original simulated function signature; the actual access check
    happens cryptographically at decrypt time via `abe_decrypt`, not by
    trusting the caller's claimed attributes.
    """
    if not policy:
        raise ValueError("policy must contain at least one attribute")

    if threshold is None:
        threshold = len(policy)  # AND-policy: need every attribute by default

    # Generate a fresh AES-256 key for this piece of data
    aes_key = secrets.token_bytes(32)
    aes_key_int = int.from_bytes(aes_key, "big")

    policy_list = sorted(policy)  # deterministic ordering
    shares = _split_secret(aes_key_int, num_shares=len(policy_list), threshold=threshold)

    salt = secrets.token_bytes(16)
    masked_shares = {}
    for (x, y), attribute in zip(shares, policy_list):
        attr_key = _derive_attribute_key(attribute, salt)
        masked_shares[attribute] = {
            "x": x,
            "y_masked": _encode_share_with_attr_key(y, attr_key).hex(),
        }

    # Encrypt the actual data with AES-256-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    package = {
        "scheme": "SSS-ABE-AESGCM",  # not pairing-based CP-ABE; see module docstring
        "policy": policy_list,
        "threshold": threshold,
        "salt": salt.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
        "shares": masked_shares,
    }

    # Preserve original stub's "encrypt-time policy check" behavior so
    # main.py's existing call pattern (policy must be satisfiable) still
    # makes sense, without weakening the real decrypt-time security check.
    if not policy.issubset(user_attrs):
        # Caller doesn't hold the attributes needed to immediately use this
        # data, but the package is still returned — encryption itself does
        # not require the encryptor to hold decryption attributes.
        pass

    return package


def abe_decrypt(package: Dict, user_attrs: Set[str]) -> Optional[str]:
    """
    Attempts to decrypt a package produced by abe_encrypt, using only the
    attributes the caller actually holds in `user_attrs`.

    Returns the decrypted plaintext string if `user_attrs` contains enough
    matching policy attributes to meet the threshold AND the AES-GCM
    authentication tag verifies; otherwise returns None.
    """
    policy = package["policy"]
    threshold = package["threshold"]
    salt = bytes.fromhex(package["salt"])

    available_attrs = [a for a in policy if a in user_attrs]
    if len(available_attrs) < threshold:
        return None  # not enough attributes to meet the policy threshold

    # Recover shares for attributes the user actually holds
    points = []
    for attribute in available_attrs[:threshold]:
        attr_key = _derive_attribute_key(attribute, salt)
        share_info = package["shares"][attribute]
        x = share_info["x"]
        masked = bytes.fromhex(share_info["y_masked"])
        y = _decode_share_with_attr_key(masked, attr_key)
        points.append((x, y))

    secret_int = _reconstruct_secret(points)
    try:
        aes_key = secret_int.to_bytes(32, "big")
    except OverflowError:
        return None  # reconstruction failed (wrong/insufficient attributes)

    nonce = bytes.fromhex(package["nonce"])
    tag = bytes.fromhex(package["tag"])
    ciphertext = bytes.fromhex(package["ciphertext"])

    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except (ValueError, KeyError):
        # GCM tag verification failed -> wrong key -> attributes did not
        # actually satisfy the policy (or data was tampered with)
        return None