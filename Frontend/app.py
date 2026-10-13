"""Giao diện CryptoShield (Streamlit).

Chạy trong thư mục P256_MLKEM768:   python -m streamlit run Frontend/app.py
Giao diện chỉ gọi lại code của cả nhóm: ThangV2 (trao đổi khóa), Encryp_Package (mã hóa + ký),
Dang_Attack_Lab (tấn công), Network (gửi/nhận qua mạng), Benchmark (đo hiệu năng).
"""

import contextlib
import csv
import io
import sys
import tempfile
import threading
import uuid
from pathlib import Path

import streamlit as st

GOC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GOC))  # để import code của cả nhóm
from ThangV2 import hybrid_kex
from Dang_Attack_Lab import attack_lab
from Benchmark import benchmark
from Network import receiver, sender
from Network.mang import PORT, dia_chi_ip, van_tay

st.set_page_config(page_title="CryptoShield", layout="wide")


def hex_ngan(b: bytes, n=24):
    """Hiện n byte đầu dạng hex cho gọn."""
    return b[:n].hex() + ("..." if len(b) > n else "")


# ------------------------------------------------------------------ 1. Tổng quan
def trang_tong_quan():
    st.title("CryptoShield: truyền tệp an toàn ECDH + ML-KEM")
    st.graphviz_chart("""digraph {
        rankdir=LR; node [shape=box, style=rounded, fontsize=20]
        K [label="ECDH +\\nML-KEM-768"]; H [label="HKDF\\n→ khóa phiên"]; E [label="AES-GCM\\n+ chữ ký"]
        N [label="Gửi qua\\nTCP"]; B [label="Bob kiểm tra\\nrồi giải mã"]
        K -> H -> E -> N -> B
    }""")

    bang1 = benchmark.OUT / "thi_nghiem_1.csv"
    if bang1.exists():
        dong = {(d["Cài đặt"], d["Lược đồ"]): d for d in csv.DictReader(open(bang1, encoding="utf-8-sig"))}
        ecdh, kem = dong[(benchmark.NHOM, "ECDH P-256")], dong[(benchmark.NHOM, "ML-KEM-768")]
        st.subheader("Một lần thiết lập khóa (số liệu từ Benchmark, code của nhóm)")
        for ten, d in (("ECDH P-256", ecdh), ("ML-KEM-768", kem)):
            c = st.columns(2)
            c[0].metric(f"{ten}: thời gian", f"{float(d['Tổng (ms)']):.1f} ms")
            c[1].metric(f"{ten}: gửi qua mạng", f"{d['Tổng gửi qua mạng (B)']} byte")
    st.caption("Địa chỉ IP của máy này: " + ", ".join(dia_chi_ip()))


# ------------------------------------------------------------------ 2. Gửi tệp (máy Alice)
def trang_gui():
    st.title("Gửi tệp (máy Alice)")
    st.info(f"Dấu vân tay khóa ký của Alice: **{van_tay(sender.khoa_ky_cua_alice()[1])}** (đọc cho Bob qua kênh khác)")
    tep = st.file_uploader("Chọn tệp cần gửi")
    c = st.columns(3)
    ip = c[0].text_input("Địa chỉ IP máy Bob", "127.0.0.1")
    port = c[1].number_input("Cổng", value=PORT, step=1)
    vt_bob = c[2].text_input("Vân tay khóa của Bob (để trống = không xác thực)")

    if st.button("Gửi cho Bob", type="primary", disabled=tep is None):
        thu_muc = Path(tempfile.mkdtemp())
        duong_dan = thu_muc / tep.name  # giữ tên tệp gốc để Bob lưu đúng tên
        duong_dan.write_bytes(tep.getvalue())
        try:
            tra_loi, so_lieu = sender.gui_tep(ip, duong_dan, int(port), vt_bob)
        except sender.SaiVanTay as e:
            st.error(f"DỪNG, không gửi tệp: {e}")
            return
        except OSError as e:
            st.error(f"Không kết nối được tới Bob: {e}")
            return
        (st.success if tra_loi.startswith("CHAP NHAN") else st.error)("Bob trả lời: " + tra_loi)
        st.write("Khóa của Bob:", so_lieu["van_tay_bob"], "(đã xác thực)" if so_lieu["da_xac_thuc"] else "(chưa xác thực)")
        c = st.columns(4)
        c[0].metric("Thiết lập khóa", f"{so_lieu['thiet_lap_khoa_ms']:.1f} ms")
        c[1].metric("Mã hóa + ký", f"{so_lieu['ma_hoa_ms']:.1f} ms")
        c[2].metric("Gửi + Bob xử lý", f"{so_lieu['gui_ms']:.1f} ms")
        c[3].metric("Kích thước package", f"{so_lieu['goi_tin_byte']} byte")


# ------------------------------------------------------------------ 3. Nhận tệp (máy Bob)
@st.cache_resource
def may_bob():
    """Trạng thái máy Bob dùng chung cho mọi lần tải lại trang (máy nhận chỉ bật một lần)."""
    return {"dang_chay": False, "log": [], "van_tay_alice": ""}


def bat_may_bob(port, vt_alice):
    m = may_bob()

    def chay():
        try:
            receiver.chay_bob(port, "0.0.0.0", vt_alice, m["log"].append)
        except OSError as e:  # ví dụ cổng đang bị chương trình khác dùng
            m["log"].append(f"LOI: khong mo duoc cong {port}: {e}")
            m["dang_chay"] = False

    m.update(dang_chay=True, van_tay_alice=vt_alice)
    threading.Thread(target=chay, daemon=True).start()


def trang_nhan():
    st.title("Nhận tệp (máy Bob)")
    ecdh, kem = receiver.khoa_cua_bob()
    st.info(f"Dấu vân tay khóa của Bob: **{van_tay(ecdh.public_key, kem.public_key)}** (đọc cho Alice qua kênh khác)")
    m = may_bob()
    if not m["dang_chay"]:
        c = st.columns(2)
        port = c[0].number_input("Cổng", value=PORT, step=1)
        vt_alice = c[1].text_input("Vân tay khóa ký của Alice (để trống = không xác thực)")
        if st.button("Bật máy nhận", type="primary"):
            bat_may_bob(int(port), vt_alice)
            st.rerun()
    else:
        st.success("Máy nhận đang chạy tại " + ", ".join(dia_chi_ip())
                   + (" | có xác thực khóa ký của Alice" if m["van_tay_alice"] else " | CHƯA xác thực khóa ký của Alice"))
    hop_thu()


@st.fragment(run_every="2s")  # tự làm mới phần này 2 giây một lần
def hop_thu():
    st.subheader("Nhật ký nhận")
    st.code("\n".join(reversed(may_bob()["log"])) or "(chưa có gì)")
    st.subheader("Tệp đã nhận")
    for tep in sorted(receiver.THU_MUC_NHAN.glob("*")) if receiver.THU_MUC_NHAN.exists() else []:
        st.download_button(f"Tải về {tep.name} ({tep.stat().st_size} byte)", tep.read_bytes(), tep.name, key=tep.name)


# ------------------------------------------------------------------ 4. Key Inspector
def trang_key_inspector():
    st.title("Key Inspector: xem một lần trao đổi khóa hybrid")
    if not st.button("Tạo một phiên trao đổi khóa mới", type="primary"):
        return
    bob_ecdh, bob_kem = hybrid_kex.generate_receiver_keys()                        # Bob tạo khóa
    alice = hybrid_kex.sender_establish(bob_ecdh.public_key, bob_kem.public_key)   # Alice: khóa tạm + Encaps
    header = hybrid_kex.make_package_header(alice, group_id="demo", message_id=str(uuid.uuid4()),
                                            filename="demo.txt", plaintext_size=0, plaintext_hash=bytes(32))
    bob = hybrid_kex.receiver_establish(bob_ecdh.private_key, bob_kem.private_key, header)  # Bob: ECDH + Decaps

    cac_khoa = [
        ("Bob → Alice", "Khóa công khai ECDH của Bob", bob_ecdh.public_key),
        ("Bob → Alice", "Khóa công khai ML-KEM-768 của Bob", bob_kem.public_key),
        ("Chỉ Bob giữ", "Khóa riêng ECDH của Bob", bob_ecdh.private_key),
        ("Chỉ Bob giữ", "Khóa riêng ML-KEM-768 của Bob", bob_kem.private_key),
        ("Alice → Bob", "Khóa công khai tạm ECDH của Alice", alice.sender_ecdh_public),
        ("Alice → Bob", "Ciphertext ML-KEM-768", alice.mlkem_ciphertext),
        ("Alice → Bob", "Transcript hash", alice.transcript_hash),
        ("Không gửi", "Khóa phiên Alice tính ra", alice.session_key),
        ("Không gửi", "Khóa phiên Bob tính ra", bob.session_key),
    ]
    st.dataframe([{"Đi đâu": d, "Thành phần": ten, "Kích thước (byte)": len(b), "Giá trị (hex, rút gọn)": hex_ngan(b)}
                  for d, ten, b in cac_khoa], hide_index=True)
    if alice.session_key == bob.session_key:
        st.success("Hai bên tính ra cùng một khóa phiên 32 byte mà khóa này không hề được gửi qua mạng.")


# ------------------------------------------------------------------ 5. Attack Lab
DEMO = {
    "1. Luồng bình thường": attack_lab.normal_flow,
    "2. Sửa ciphertext": attack_lab.demo_tamper_ciphertext,
    "3. Sửa thông tin trao đổi khóa (header)": attack_lab.demo_tamper_header,
    "4. Phát lại gói tin (replay)": attack_lab.demo_replay_attack,
    "5. Thay khóa công khai (MITM)": attack_lab.demo_key_substitution,
}


def trang_attack_lab():
    st.title("Attack Lab")
    st.caption("Chạy các demo trong Dang_Attack_Lab/attack_lab.py của Đăng.")
    for ten, ham in DEMO.items():
        if st.button(ten):
            dau_ra = io.StringIO()
            with contextlib.redirect_stdout(dau_ra):  # bắt chữ demo in ra để hiện lên trang
                ham()
            st.code(dau_ra.getvalue())


# ------------------------------------------------------------------ 6. Benchmark
def trang_benchmark():
    st.title("Benchmark: ECDH và ML-KEM")
    if st.button("Chạy lại benchmark (khoảng 25 giây)"):
        with st.spinner("Đang đo..."):
            benchmark.main()
    if not (benchmark.OUT / "thi_nghiem_1.csv").exists():
        st.warning("Chưa có kết quả, hãy bấm nút chạy benchmark.")
        return
    st.text((benchmark.OUT / "moi_truong.txt").read_text(encoding="utf-8"))
    for ten_csv, anh in [("thi_nghiem_1.csv", ["1_thoi_gian_thiet_lap_khoa.png", "2_kich_thuoc.png"]),
                         ("thi_nghiem_2.csv", ["3_truyen_tep.png"])]:
        st.subheader(ten_csv)
        st.dataframe(list(csv.DictReader(open(benchmark.OUT / ten_csv, encoding="utf-8-sig"))), hide_index=True)
        for a in anh:
            st.image(str(benchmark.OUT / a))


TRANG = {
    "Tổng quan": trang_tong_quan,
    "Gửi tệp (Alice)": trang_gui,
    "Nhận tệp (Bob)": trang_nhan,
    "Key Inspector": trang_key_inspector,
    "Attack Lab": trang_attack_lab,
    "Benchmark": trang_benchmark,
}
TRANG[st.sidebar.radio("CryptoShield", list(TRANG))]()
