"""Máy gửi (Alice): lấy khóa công khai của Bob qua mạng, thiết lập khóa hybrid, mã hóa + ký tệp rồi gửi.

Chạy trong thư mục P256_MLKEM768:
    python Network/sender.py <IP máy Bob> <tệp>
    python Network/sender.py <IP máy Bob> <tệp> --van-tay-bob "xxxx xxxx xxxx xxxx"   (có xác thực khóa Bob)
"""

import argparse
import secrets
import socket
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # để import code của Thắng và Tân
from ThangV2 import classical_kex, hybrid_kex
from Encryp_Package.pipeline import seal_file
from Encryp_Package.signature import xuat_pub_key
from Network.mang import PORT, cung_van_tay, gui, nhan, van_tay

FILE_KHOA = Path(__file__).resolve().parent / "khoa" / "alice.txt"


class SaiVanTay(Exception):
    """Khóa nhận qua mạng không khớp vân tay của Bob: có thể đang bị MITM thay khóa."""


def khoa_ky_cua_alice():
    """Khóa ký ECDSA dài hạn của Alice. Lưu 32 byte bí mật để lần sau tạo lại đúng khóa cũ (vân tay không đổi)."""
    if not FILE_KHOA.exists():
        FILE_KHOA.parent.mkdir(exist_ok=True)
        FILE_KHOA.write_text(secrets.token_hex(32))
    so = int.from_bytes(bytes.fromhex(FILE_KHOA.read_text()), "big") % (classical_kex.N - 1) + 1
    khoa_rieng = ec.derive_private_key(so, ec.SECP256R1())
    return khoa_rieng, xuat_pub_key(khoa_rieng.public_key())


def gui_tep(ip_bob, duong_dan, port=PORT, van_tay_bob=""):
    """Gửi một tệp cho Bob. Trả về (câu trả lời của Bob, số liệu đo được)."""
    khoa_rieng, khoa_ky_pem = khoa_ky_cua_alice()
    with socket.create_connection((ip_bob, port), timeout=60) as s:
        # Bước 1-2: nhận khóa công khai của Bob, so vân tay nếu có
        ecdh_pub, mlkem_pub = nhan(s), nhan(s)
        vt = van_tay(ecdh_pub, mlkem_pub)
        if van_tay_bob and not cung_van_tay(vt, van_tay_bob):
            raise SaiVanTay(f"khoa nhan duoc co van tay {vt}, khong phai cua Bob -> co the bi MITM thay khoa")

        # Thiết lập khóa hybrid rồi mã hóa + ký tệp (code của Thắng và Tân)
        t0 = time.perf_counter()
        phien = hybrid_kex.sender_establish(ecdh_pub, mlkem_pub)
        t1 = time.perf_counter()
        goi_tin = seal_file(str(duong_dan), phien, khoa_rieng)
        t2 = time.perf_counter()

        # Bước 3-5: gửi khóa ký + package, chờ Bob trả lời
        gui(s, khoa_ky_pem)
        gui(s, goi_tin)
        tra_loi = nhan(s).decode()
        t3 = time.perf_counter()

    return tra_loi, {"van_tay_bob": vt, "da_xac_thuc": bool(van_tay_bob),
                     "thiet_lap_khoa_ms": (t1 - t0) * 1000, "ma_hoa_ms": (t2 - t1) * 1000,
                     "gui_ms": (t3 - t2) * 1000, "goi_tin_byte": len(goi_tin)}


def main():
    ap = argparse.ArgumentParser(description="May gui (Alice)")
    ap.add_argument("ip_bob", help="dia chi IP may Bob (hoac may trung gian)")
    ap.add_argument("tep", help="tep can gui")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--van-tay-bob", default="", help="dau van tay khoa cua Bob, nhan qua kenh khac")
    args = ap.parse_args()

    print("Dau van tay khoa ky cua Alice:", van_tay(khoa_ky_cua_alice()[1]), " <- doc cho Bob qua kenh khac")
    try:
        tra_loi, so_lieu = gui_tep(args.ip_bob, args.tep, args.port, args.van_tay_bob)
    except SaiVanTay as e:
        sys.exit(f"DUNG: {e}")
    print("Khoa cua Bob:", so_lieu["van_tay_bob"], "(da xac thuc)" if so_lieu["da_xac_thuc"] else "(CHUA xac thuc)")
    print("Bob tra loi:", tra_loi)
    print(f"Thiet lap khoa {so_lieu['thiet_lap_khoa_ms']:.1f} ms | ma hoa + ky {so_lieu['ma_hoa_ms']:.1f} ms | "
          f"gui + Bob xu ly {so_lieu['gui_ms']:.1f} ms | package {so_lieu['goi_tin_byte']} byte")


if __name__ == "__main__":
    main()
