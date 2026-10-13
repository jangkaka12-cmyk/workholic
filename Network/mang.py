"""Phần dùng chung cho máy gửi (Alice) và máy nhận (Bob).

Giao thức: mỗi lần gửi tệp là một kết nối TCP gồm 5 thông điệp
    1. Bob   -> Alice : khóa công khai ECDH P-256 của Bob (33 byte)
    2. Bob   -> Alice : khóa công khai ML-KEM-768 của Bob (1184 byte)
    3. Alice -> Bob   : khóa công khai dùng để kiểm tra chữ ký của Alice (PEM)
    4. Alice -> Bob   : package (JSON do Encryp_Package tạo)
    5. Bob   -> Alice : kết quả, ví dụ "CHAP NHAN: ..." hoặc "TU CHOI: ..."
Mỗi thông điệp = 4 byte độ dài + nội dung.

Bản thân kênh TCP không mã hóa: ai đứng giữa cũng đọc, sửa, gửi lại được.
Bảo vệ nằm trong package (AES-GCM, chữ ký, transcript hash) và ở bước so dấu vân tay khóa.
"""

import hashlib
import socket

PORT = 9000


def gui(sock, du_lieu: bytes):
    sock.sendall(len(du_lieu).to_bytes(4, "big") + du_lieu)


def nhan(sock) -> bytes:
    do_dai = int.from_bytes(doc_du(sock, 4), "big")
    return doc_du(sock, do_dai)


def doc_du(sock, n):
    """TCP có thể trả dữ liệu thành nhiều mảnh nên phải đọc tới khi đủ n byte."""
    buf = bytearray()
    while len(buf) < n:
        manh = sock.recv(min(n - len(buf), 1 << 20))
        if not manh:
            raise ConnectionError("ket noi bi dong giua chung")
        buf += manh
    return bytes(buf)


def van_tay(*khoa: bytes) -> str:
    """Dấu vân tay = 16 ký tự hex đầu của SHA-256(khóa), đủ ngắn để đọc cho nhau qua điện thoại."""
    h = hashlib.sha256(b"".join(khoa)).hexdigest()[:16]
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def cung_van_tay(a: str, b: str) -> bool:
    return a.replace(" ", "").lower() == b.replace(" ", "").lower()


def dia_chi_ip():
    """Các địa chỉ IP của máy này, để Bob đọc cho Alice biết mà kết nối."""
    try:
        ds = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        ds = []
    return [ip for ip in ds if not ip.startswith("127.")] or ["127.0.0.1"]
