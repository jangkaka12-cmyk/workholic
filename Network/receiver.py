"""Máy nhận (Bob): mở cổng chờ Alice, đưa khóa công khai, nhận package, kiểm tra rồi giải mã.

Chạy trong thư mục P256_MLKEM768:
    python Network/receiver.py
    python Network/receiver.py --van-tay-alice "xxxx xxxx xxxx xxxx"   (có xác thực khóa ký của Alice)
Tệp nhận được lưu vào Network/nhan_duoc/.
"""

import argparse
import secrets
import socket
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # để import code của Thắng và Tân
from ThangV2 import classical_kex, hybrid_kex
from Encryp_Package.package import dec_package
from Encryp_Package.pipeline import open_file
from Network.mang import PORT, cung_van_tay, dia_chi_ip, gui, nhan, van_tay

THU_MUC = Path(__file__).resolve().parent
FILE_KHOA = THU_MUC / "khoa" / "bob.txt"
THU_MUC_NHAN = THU_MUC / "nhan_duoc"


def khoa_cua_bob():
    """Khóa dài hạn của Bob (ECDH + ML-KEM-768).

    Lần đầu tạo 96 byte ngẫu nhiên và lưu lại; các lần sau tạo lại đúng cặp khóa cũ từ 96 byte đó,
    nhờ vậy dấu vân tay của Bob không đổi giữa các lần chạy.
    """
    if not FILE_KHOA.exists():
        FILE_KHOA.parent.mkdir(exist_ok=True)
        FILE_KHOA.write_text(secrets.token_hex(96))
    goc = bytes.fromhex(FILE_KHOA.read_text())
    so_ecdh = int.from_bytes(goc[:32], "big") % (classical_kex.N - 1) + 1  # khóa riêng ECDH phải trong [1, N-1]
    return hybrid_kex.generate_receiver_keys(ecdh_private_scalar=so_ecdh, mlkem_seed=goc[32:])


def mo_goi(khoa_bob, khoa_ky_pem, goi_tin, van_tay_alice, da_nhan):
    """Kiểm tra và giải mã một package. Trả về (header, bản rõ); sai ở đâu thì báo lỗi ở đó."""
    # 1. Khóa ký gửi kèm có đúng là của Alice không (chỉ kiểm tra được khi Bob biết vân tay của Alice)
    if van_tay_alice and not cung_van_tay(van_tay(khoa_ky_pem), van_tay_alice):
        raise ValueError("khoa ky khong phai cua Alice (sai dau van tay) -> nghi bi MITM")

    # 2. Chống phát lại: mỗi message_id chỉ được nhận một lần
    header = dec_package(goi_tin).header
    if header.message_id in da_nhan:
        raise ValueError(f"message_id {header.message_id} da nhan roi -> goi bi phat lai (replay)")

    # 3. Tính lại khóa phiên từ khóa riêng của Bob (kiểm tra luôn transcript hash)
    ecdh, kem = khoa_bob
    phien = hybrid_kex.receiver_establish(ecdh.private_key, kem.private_key, header)

    # 4. Kiểm tra chữ ký, giải mã AES-GCM, kiểm tra kích thước + SHA-256 (code của Tân)
    ban_ro = open_file(goi_tin, phien, load_pem_public_key(khoa_ky_pem))

    da_nhan.add(header.message_id)  # chỉ ghi nhận sau khi package hợp lệ
    return header, ban_ro


def phuc_vu_mot_lan(conn, khoa_bob, van_tay_alice, da_nhan):
    """Xử lý một kết nối của Alice theo đúng 5 bước trong mang.py. Trả về câu kết quả."""
    try:
        gui(conn, khoa_bob[0].public_key)
        gui(conn, khoa_bob[1].public_key)
        khoa_ky_pem, goi_tin = nhan(conn), nhan(conn)
        header, ban_ro = mo_goi(khoa_bob, khoa_ky_pem, goi_tin, van_tay_alice, da_nhan)
        THU_MUC_NHAN.mkdir(exist_ok=True)
        (THU_MUC_NHAN / header.filename).write_bytes(ban_ro)  # package.py đã chặn tên tệp chứa đường dẫn
        ket_qua = f"CHAP NHAN: da nhan {header.filename} ({len(ban_ro)} byte)"
    except ConnectionError:
        return "NGAT: Alice dong ket noi truoc khi gui package (vd. Alice thay sai van tay nen dung lai)"
    except Exception as e:
        ket_qua = f"TU CHOI: {type(e).__name__}: {e}"
    try:
        gui(conn, ket_qua.encode())
    except OSError:
        pass  # Alice đã ngắt kết nối
    return ket_qua


def chay_bob(port=PORT, host="0.0.0.0", van_tay_alice="", ghi_log=print):
    """Chờ Alice kết nối mãi mãi; mỗi lần nhận xong thì gọi ghi_log(dòng kết quả)."""
    khoa_bob = khoa_cua_bob()
    da_nhan = set()  # các message_id đã nhận (mất khi tắt Bob)
    with socket.create_server((host, port)) as server:
        server.settimeout(1)  # để Ctrl+C dừng được trên Windows
        while True:
            try:
                conn, (ip, _) = server.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(60)
                ghi_log(f"[{ip}] " + phuc_vu_mot_lan(conn, khoa_bob, van_tay_alice, da_nhan))


def main():
    ap = argparse.ArgumentParser(description="May nhan (Bob)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default="0.0.0.0", help="0.0.0.0 = nhan ket noi tu moi may trong mang")
    ap.add_argument("--van-tay-alice", default="", help="dau van tay khoa ky cua Alice, nhan qua kenh khac")
    args = ap.parse_args()

    ecdh, kem = khoa_cua_bob()
    print("Bob dang cho tai:", ", ".join(f"{ip}:{args.port}" for ip in dia_chi_ip()))
    print("Dau van tay khoa cua Bob:", van_tay(ecdh.public_key, kem.public_key), " <- doc cho Alice qua kenh khac")
    if not args.van_tay_alice:
        print("CANH BAO: chua co van tay cua Alice -> tin moi khoa ky gui kem (MITM co the gia mao)")
    print("Nhan Ctrl+C de dung.\n")
    chay_bob(args.port, args.host, args.van_tay_alice)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Da dung Bob.")
