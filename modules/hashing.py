"""
modules/hashing.py - Phan B.2.2: Ham bam, HMAC va hieu ung thac.
Module thuan ham (khong Flask): app.py goi truc tiep va tu jsonify ket qua.
Loi dau vao sai -> raise ValueError (app.py nen bat va tra 400).
"""
import hashlib
import hmac
import os
import statistics
import time

ALGOS = {
    "sha256": {"bits": 256, "secure": True},
    "sha1":   {"bits": 160, "secure": False},
    "md5":    {"bits": 128, "secure": False},
}
WARN = {
    "sha1": "SHA-1 da bi tim ra va cham (SHAttered, 2017) - khong dung cho bao mat.",
    "md5":  "MD5 da bi pha vo (va cham tim duoc trong vai giay) - khong dung cho bao mat.",
}
MIN_BENCH_BYTES = 10 * 1024 * 1024


# ---------- tien ich ----------
def bit_diff(a: bytes, b: bytes) -> int:
    """So bit khac nhau giua hai chuoi byte cung do dai (khoang cach Hamming)."""
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_one_char(text: str, pos: int) -> str:
    """Sua dung 1 ky tu tai vi tri pos (tang ma ky tu len 1)."""
    n = ord(text[pos]) + 1
    if 0xD800 <= n <= 0xDFFF or n > 0x10FFFF:   # tranh vung surrogate / ngoai Unicode
        n = ord(text[pos]) - 1
    return text[:pos] + chr(n) + text[pos + 1:]


def _to_bytes(x) -> bytes:
    if x is None:
        return b""
    return x if isinstance(x, (bytes, bytearray)) else str(x).encode("utf-8")


# ---------- ham chinh ----------
def digest_all(data) -> dict:
    """{'sha256': 'hex', 'sha1': 'hex', 'md5': 'hex'} - moi thuat toan la mot chuoi hex."""
    data = _to_bytes(data)
    return {name: hashlib.new(name, data).hexdigest() for name in ALGOS}


def hash_data(data) -> dict:
    """Ban chi tiet: do dai + hex/bits/canh bao cho tung thuat toan."""
    data = _to_bytes(data)
    flat = digest_all(data)
    return {"length_bytes": len(data), **flat,
            "hashes": {n: {"hex": flat[n], "bits": ALGOS[n]["bits"], "warning": WARN.get(n)}
                       for n in ALGOS}}


# bi danh de khop nhieu cach dat ten trong app.py
hash_all = compute_hashes = hash_text = hash_bytes = hash_data


def _to_text(x) -> str:
    if x is None:
        return ""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).decode("utf-8", "replace")
    return str(x)


def avalanche(text, text2=None, position=None) -> dict:
    """So sanh so bit khac nhau giua hash(text) va hash(text2).
    text2 de trong/None -> tu tang ky tu tai `position` (mac dinh ky tu cuoi) len 1."""
    text = _to_text(text)
    text2 = _to_text(text2)
    if not text:
        raise ValueError("Hay nhap van ban khong rong.")
    if not text2:
        pos = len(text) - 1 if position in (None, "") else int(position)
        if not 0 <= pos < len(text):
            raise ValueError("Vi tri ky tu ngoai pham vi.")
        text2 = flip_one_char(text, pos)
    res = {}
    for name, info in ALGOS.items():
        h1 = hashlib.new(name, text.encode()).digest()
        h2 = hashlib.new(name, text2.encode()).digest()
        d = bit_diff(h1, h2)
        res[name] = {"hash1": h1.hex(), "hash2": h2.hex(),
                     "diff_bits": d, "total_bits": info["bits"],
                     "ratio": round(d / info["bits"], 4)}
    main = res["sha256"]
    return {"original": text, "modified": text2, "text1": text, "text2": text2,
            "hash1": main["hash1"], "hash2": main["hash2"],
            "diff_bits": main["diff_bits"], "total_bits": main["total_bits"],
            "ratio": main["ratio"], "result": res}


def hmac_sha256(key, message, tag=None) -> dict:
    """Tinh HMAC-SHA256; neu co `tag` thi kiem tra bang so sanh hang thoi gian."""
    t = hmac.new(_to_bytes(key), _to_bytes(message), hashlib.sha256).hexdigest()
    out = {"tag": t}
    if tag is not None and tag != "":
        ok = hmac.compare_digest(t.encode(), str(tag).strip().lower().encode())
        out["verify"] = {"valid": ok,
                         "message": "The hop le" if ok else
                         "The khong hop le (sai khoa hoac thong diep bi sua)"}
    return out


def benchmark(data=None, repeat: int = 20) -> dict:
    """Do thoi gian bam cho tung ham; data=None -> tu sinh 10 MB ngau nhien."""
    data = os.urandom(MIN_BENCH_BYTES) if data is None else _to_bytes(data)
    if len(data) < MIN_BENCH_BYTES:
        raise ValueError("Can file >= 10 MB (bo trong de tu sinh 10 MB ngau nhien).")
    repeat = max(1, min(int(repeat), 100))
    size_mb = len(data) / (1024 * 1024)
    res = {}
    for name in ALGOS:
        ts = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            hashlib.new(name, data).digest()
            ts.append((time.perf_counter() - t0) * 1000)
        mean = statistics.mean(ts)
        res[name] = {"mean_ms": round(mean, 2),
                     "stdev_ms": round(statistics.pstdev(ts), 2),
                     "throughput_mb_s": round(size_mb / (mean / 1000), 1)}
    return {"size_mb": round(size_mb, 2), "repeat": repeat, "result": res}
