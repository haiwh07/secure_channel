"""
hashing.py - Phan B.2.2: Ham bam, HMAC va hieu ung thac.

Tich hop vao Flask app chung:
    from modules.hashing import hash_bp
    app.register_blueprint(hash_bp)

Chay rieng:
    python -m modules.hashing
    -> http://127.0.0.1:5001/hash
"""

import hashlib
import hmac
import os
import statistics
import time

from flask import Blueprint, Flask, jsonify, request

hash_bp = Blueprint("hash_bp", __name__)

ALGOS = {
    "sha256": {"bits": 256, "secure": True},
    "sha1": {"bits": 160, "secure": False},
    "md5": {"bits": 128, "secure": False},
}

WARN = {
    "sha1": (
        "SHA-1 da bi tim ra va cham (SHAttered, 2017) - "
        "khong dung cho bao mat."
    ),
    "md5": (
        "MD5 da bi pha vo (va cham tim duoc trong vai giay) - "
        "khong dung cho bao mat."
    ),
}


# =========================================================
# HAM TIEN ICH
# =========================================================

def bit_diff(a: bytes, b: bytes) -> int:
    """Dem so bit khac nhau giua hai chuoi byte."""
    if len(a) != len(b):
        raise ValueError("Hai chuoi byte phai co cung do dai.")

    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def digest_all(data: bytes) -> dict:
    """Tinh SHA-256, SHA-1 va MD5."""
    result = {}

    for name, info in ALGOS.items():
        result[name] = {
            "hex": hashlib.new(name, data).hexdigest(),
            "bits": info["bits"],
            "warning": WARN.get(name),
        }

    return result


def get_input_bytes() -> bytes:
    """Lay du lieu tu file upload, JSON hoac form."""
    file = request.files.get("file")

    if file:
        return file.read()

    if request.is_json:
        body = request.get_json(silent=True) or {}
        return str(body.get("text", "")).encode("utf-8")

    return request.form.get("text", "").encode("utf-8")


def flip_one_char(text: str, pos: int) -> str:
    """Thay doi mot ky tu tai vi tri pos."""
    if not 0 <= pos < len(text):
        raise ValueError("Vi tri ky tu ngoai pham vi.")

    original = ord(text[pos])
    changed = original + 1

    if changed > 0x10FFFF or 0xD800 <= changed <= 0xDFFF:
        changed = original - 1

    return text[:pos] + chr(changed) + text[pos + 1:]


# =========================================================
# CAC HAM TUONG THICH VOI MODULE KHAC
# =========================================================

def avalanche(text: str, position: int | None = None) -> dict:
    """
    Phan tich hieu ung thac.
    Thay doi mot ky tu va so sanh cac ma bam truoc/sau.
    """
    if not text:
        raise ValueError("Van ban khong duoc rong.")

    if position is None:
        position = len(text) - 1

    if not 0 <= position < len(text):
        raise ValueError("Vi tri ky tu ngoai pham vi.")

    modified = flip_one_char(text, position)
    result = {}

    for name, info in ALGOS.items():
        hash1 = hashlib.new(name, text.encode("utf-8")).digest()
        hash2 = hashlib.new(name, modified.encode("utf-8")).digest()
        diff = bit_diff(hash1, hash2)

        result[name] = {
            "hash1": hash1.hex(),
            "hash2": hash2.hex(),
            "diff_bits": diff,
            "total_bits": info["bits"],
            "ratio": round(diff / info["bits"], 4),
        }

    return {
        "original": text,
        "modified": modified,
        "position": position,
        "result": result,
    }


def hmac_sha256(key: str | bytes, message: str | bytes) -> str:
    """Tinh HMAC-SHA256 va tra ve chuoi hex."""
    if isinstance(key, str):
        key = key.encode("utf-8")

    if isinstance(message, str):
        message = message.encode("utf-8")

    return hmac.new(key, message, hashlib.sha256).hexdigest()


def benchmark(data: bytes | str | None = None, repeat: int = 20) -> dict:
    """
    Do thoi gian bam SHA-256, SHA-1 va MD5.

    Neu khong truyen data, tu tao 10 MiB du lieu ngau nhien.
    """
    if data is None:
        data = os.urandom(10 * 1024 * 1024)
    elif isinstance(data, str):
        data = data.encode("utf-8")

    if len(data) < 10 * 1024 * 1024:
        raise ValueError("Du lieu benchmark phai co it nhat 10 MiB.")

    repeat = max(1, min(int(repeat), 100))
    size_mb = len(data) / (1024 * 1024)
    result = {}

    for name in ALGOS:
        times = []

        for _ in range(repeat):
            start = time.perf_counter()
            hashlib.new(name, data).digest()
            times.append((time.perf_counter() - start) * 1000)

        mean_ms = statistics.mean(times)

        result[name] = {
            "mean_ms": round(mean_ms, 2),
            "stdev_ms": round(statistics.pstdev(times), 2),
            "throughput_mb_s": (
                round(size_mb / (mean_ms / 1000), 1)
                if mean_ms > 0 else 0
            ),
        }

    return {
        "size_mb": round(size_mb, 2),
        "repeat": repeat,
        "result": result,
    }


# =========================================================
# API FLASK
# =========================================================

@hash_bp.post("/api/hash")
def api_hash():
    data = get_input_bytes()

    return jsonify({
        "length_bytes": len(data),
        "hashes": digest_all(data),
    })


@hash_bp.post("/api/avalanche")
def api_avalanche():
    body = request.get_json(silent=True) or {}
    text = body.get("text", "")

    if not isinstance(text, str) or not text:
        return jsonify({"error": "Hay nhap van ban khong rong."}), 400

    try:
        position = int(body.get("position", len(text) - 1))
        result = avalanche(text, position)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


@hash_bp.post("/api/hmac")
def api_hmac():
    body = request.get_json(silent=True) or {}

    key = body.get("key", "")
    message = body.get("message", "")

    if not isinstance(key, str) or not isinstance(message, str):
        return jsonify({
            "error": "Key va message phai la chuoi."
        }), 400

    tag = hmac_sha256(key, message)
    output = {"tag": tag}

    given_tag = body.get("tag")

    if given_tag is not None:
        if not isinstance(given_tag, str):
            return jsonify({"error": "Tag phai la chuoi."}), 400

        valid = hmac.compare_digest(
            tag.encode("ascii"),
            given_tag.strip().lower().encode("ascii", errors="ignore"),
        )

        output["verify"] = {
            "valid": valid,
            "message": (
                "The hop le" if valid
                else "The khong hop le (sai khoa hoac thong diep bi sua)"
            ),
        }

    return jsonify(output)


@hash_bp.post("/api/hash-benchmark")
def api_benchmark():
    """Benchmark file upload hoac du lieu ngau nhien 10 MiB."""
    file = request.files.get("file")
    data = file.read() if file else None

    try:
        repeat = int(request.form.get("repeat", 20))
        result = benchmark(data, repeat)
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result)


# =========================================================
# GIAO DIEN WEB
# =========================================================

PAGE = """<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hàm băm &amp; HMAC</title>
<style>
body {
    font-family: sans-serif;
    max-width: 900px;
    margin: 20px auto;
    padding: 0 14px;
}
textarea, input {
    width: 100%;
    box-sizing: border-box;
    margin: 5px 0;
    padding: 8px;
}
button {
    padding: 8px 14px;
    margin: 5px 0;
    cursor: pointer;
}
pre {
    background: #f4f4f4;
    padding: 10px;
    overflow: auto;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}
section {
    border: 1px solid #ccc;
    padding: 12px;
    margin: 14px 0;
    border-radius: 8px;
}
</style>
</head>
<body>
<h2>B.2.2 - Hàm băm, HMAC, hiệu ứng thác</h2>

<section>
<h3>1. Băm văn bản / file</h3>
<textarea id="t" rows="3">abc</textarea>
<input type="file" id="f">
<button onclick="doHash()">Tính mã băm</button>
<pre id="o1"></pre>
</section>

<section>
<h3>2. Hiệu ứng thác</h3>
<input id="pos" type="number" placeholder="Vị trí ký tự (mặc định: ký tự cuối)">
<button onclick="doAv()">Sửa một ký tự và so sánh</button>
<pre id="o2"></pre>
</section>

<section>
<h3>3. HMAC-SHA256</h3>
<label>Khóa</label>
<input id="k" value="key">
<label>Thông điệp</label>
<input id="m" value="The quick brown fox jumps over the lazy dog">
<label>Tag cần kiểm tra (không bắt buộc)</label>
<input id="tg" placeholder="Nhập tag HMAC cần xác minh">
<button onclick="doH()">Tính / kiểm tra HMAC</button>
<pre id="o3"></pre>
</section>

<section>
<h3>4. Benchmark file từ 10 MiB</h3>
<input type="file" id="bf">
<label>Số lần lặp</label>
<input type="number" id="repeat" value="20" min="1" max="100">
<button onclick="doB()">Đo thời gian băm</button>
<pre id="o4"></pre>
</section>

<script>
async function postJSON(url, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    });
    return response.json();
}

async function doHash() {
    const fd = new FormData();
    const file = document.getElementById('f').files[0];

    if (file) {
        fd.append('file', file);
    } else {
        fd.append('text', document.getElementById('t').value);
    }

    const r = await fetch('/api/hash', {
        method: 'POST',
        body: fd
    }).then(response => response.json());

    document.getElementById('o1').textContent = r.error ||
        Object.entries(r.hashes || {}).map(([name, value]) =>
            name.toUpperCase() + ': ' + value.hex +
            (value.warning ? '\\\\n! ' + value.warning : '')
        ).join('\\\\n');
}

async function doAv() {
    const text = document.getElementById('t').value;
    const rawPosition = document.getElementById('pos').value;
    const body = {text};

    if (rawPosition !== '') {
        body.position = Number(rawPosition);
    }

    const r = await postJSON('/api/avalanche', body);

    document.getElementById('o2').textContent = r.error ||
        'Gốc: ' + r.original + ' -> Sửa: ' + r.modified + '\\\\n' +
        Object.entries(r.result).map(([name, value]) =>
            name.toUpperCase() + ': khác ' + value.diff_bits + '/' +
            value.total_bits + ' bit (' +
            (value.ratio * 100).toFixed(1) + '%)'
        ).join('\\\\n');
}

async function doH() {
    const body = {
        key: document.getElementById('k').value,
        message: document.getElementById('m').value
    };
    const givenTag = document.getElementById('tg').value;

    if (givenTag) {
        body.tag = givenTag;
    }

    const r = await postJSON('/api/hmac', body);

    document.getElementById('o3').textContent = r.error ||
        'Tag: ' + r.tag +
        (r.verify ? '\\\\n' + r.verify.message : '');
}

async function doB() {
    const fd = new FormData();
    const file = document.getElementById('bf').files[0];
    const repeat = document.getElementById('repeat').value;

    if (file) {
        fd.append('file', file);
    }

    fd.append('repeat', repeat);

    const r = await fetch('/api/hash-benchmark', {
        method: 'POST',
        body: fd
    }).then(response => response.json());

    document.getElementById('o4').textContent = r.error ||
        'Kích thước: ' + r.size_mb + ' MiB; số lần lặp: ' + r.repeat +
        '\\\\n' + Object.entries(r.result).map(([name, value]) =>
            name.toUpperCase() + ': ' + value.mean_ms +
            ' ms (+/- ' + value.stdev_ms + ' ms), ' +
            value.throughput_mb_s + ' MiB/s'
        ).join('\\\\n');
}
</script>
</body>
</html>"""


@hash_bp.get("/hash")
def page():
    return PAGE


if __name__ == "__main__":
    app = Flask(__name__)
    app.register_blueprint(hash_bp)
    app.run(host="127.0.0.1", port=5001, debug=True)
