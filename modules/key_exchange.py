"""
Module 4: Thỏa thuận khóa (Diffie-Hellman số nhỏ, ECDH P-256, DH-2048) và HKDF-SHA256.
Đáp ứng yêu cầu Phần B.2.5 của đề bài.
"""
import secrets

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC


# --------------------------------------------------------------------------- #
# DH-2048: nhóm MODP 2048-bit của RFC 3526 (Group 14), g = 2.
# PyCryptodome không có DH số nguyên nên tự cài bằng pow().
# p = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 )
# Tính trực tiếp từ công thức trong RFC để không phải chép tay 512 chữ số hex.
# --------------------------------------------------------------------------- #
def _atan_inv(x: int, one: int) -> int:
    """arctan(1/x) dạng số nguyên cố định (nhân với `one`)."""
    x2 = x * x
    term = one // x
    total = term
    n, sign = 1, -1
    while term:
        term //= x2
        n += 2
        total += sign * (term // n)
        sign = -sign
    return total


def _pi_floor(bits: int, guard: int = 64) -> int:
    """floor(2^bits * pi) bằng công thức Machin: pi = 16*atan(1/5) - 4*atan(1/239)."""
    one = 1 << (bits + guard)
    return (16 * _atan_inv(5, one) - 4 * _atan_inv(239, one)) >> guard


DH2048_P = (1 << 2048) - (1 << 1984) - 1 + (1 << 64) * (_pi_floor(1918) + 124476)
DH2048_G = 2
_P_LEN = 256  # 2048 bit = 256 byte


def _check_dh_public(y: int) -> None:
    """Từ chối giá trị công khai nằm ngoài [2, p-2] (chống small-subgroup: y = 0, 1, p-1)."""
    if not (2 <= y <= DH2048_P - 2):
        raise ValueError("Giá trị DH công khai không hợp lệ")


def toy_dh(p: int, g: int, a: int, b: int) -> dict:
    """
    Diffie-Hellman số nhỏ tự cài bằng pow() của Python.
    Mẫu chuẩn: p=23, g=5, a=6, b=15 -> A=8, B=19, K=2.
    """
    A = pow(g, a, p)
    B = pow(g, b, p)
    K_alice = pow(B, a, p)
    K_bob = pow(A, b, p)
    return {"A": A, "B": B, "K_alice": K_alice, "K_bob": K_bob}


def generate_ephemeral(kind: str):
    """
    Sinh cặp khóa tạm thời. Trả (private, public_bytes).
    kind: "ecdh" hoặc "dh2048"
    """
    if kind == "ecdh":
        priv = ECC.generate(curve="P-256")
        return priv, priv.public_key().export_key(format="DER")
    elif kind == "dh2048":
        x = secrets.randbelow(DH2048_P - 3) + 2          # x trong [2, p-2]
        y = pow(DH2048_G, x, DH2048_P)
        return x, y.to_bytes(_P_LEN, "big")
    raise ValueError(f"Loại thỏa thuận khóa không hỗ trợ: {kind}")


def derive_session_key(kind: str, my_private, peer_public_bytes: bytes,
                       info: bytes = b"secure-channel-session") -> bytes:
    """Dẫn xuất khóa phiên 32 byte từ bí mật chung qua HKDF-SHA256."""
    if kind == "ecdh":
        peer = ECC.import_key(peer_public_bytes)          # kiểm tra điểm nằm trên đường cong
        if peer.curve != my_private.curve:
            raise ValueError("Hai khóa khác đường cong")
        shared_point = peer.pointQ * int(my_private.d)    # pointQ là thuộc tính, KHÔNG phải point()
        shared_secret = int(shared_point.x).to_bytes(32, "big")
    elif kind == "dh2048":
        y = int.from_bytes(peer_public_bytes, "big")
        _check_dh_public(y)
        shared_secret = pow(y, my_private, DH2048_P).to_bytes(_P_LEN, "big")
    else:
        raise ValueError(f"Loại thỏa thuận khóa không hỗ trợ: {kind}")

    return HKDF(master=shared_secret, key_len=32, salt=b"secure-channel-salt-fixed",
                hashmod=SHA256, context=info)
