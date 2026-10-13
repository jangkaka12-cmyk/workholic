# Frontend: giao diện CryptoShield

Giao diện web viết bằng Streamlit, gồm một tệp `app.py`. Giao diện không tự cài thuật toán nào mà chỉ gọi lại code của cả nhóm:

| Trang | Gọi code của |
| --- | --- |
| Tổng quan | Sơ đồ luồng xử lý + số liệu chính lấy từ `Benchmark/ket_qua/` |
| Gửi tệp (Alice) | `Network/sender.py` (bên trong dùng `hybrid_kex` của Thắng, `seal_file` của Tân) |
| Nhận tệp (Bob) | `Network/receiver.py` (bên trong dùng `receiver_establish` của Thắng, `open_file` của Tân) |
| Key Inspector | `ThangV2/hybrid_kex.py`: xem từng khóa trong một lần trao đổi khóa |
| Attack Lab | `Dang_Attack_Lab/attack_lab.py` của Đăng: chạy 5 demo, hiện kết quả lên trang |
| Benchmark | `Benchmark/benchmark.py`: xem bảng, biểu đồ, chạy lại phép đo |

Nếu máy báo `Python was not found`, hãy gõ `py` thay cho `python` trong mọi lệnh bên dưới.

## Chạy giao diện

1. Mở terminal và `cd` vào thư mục `P256_MLKEM768`.
2. Cài thư viện (chỉ cần làm lần đầu):
   ```
   python -m pip install cryptography -r Frontend/requirements.txt
   ```
3. Chạy giao diện:
   ```
   python -m streamlit run Frontend/app.py
   ```
4. Trình duyệt sẽ tự mở trang `http://localhost:8501`. Nếu không tự mở, hãy tự gõ địa chỉ đó vào trình duyệt.
5. Chọn trang ở cột bên trái.
6. Muốn tắt giao diện thì quay lại terminal và nhấn **Ctrl+C**.

## Gửi tệp giữa hai máy bằng giao diện

**Trên máy Bob:**

1. Chạy giao diện như phần trên.
2. Mở trang **Nhận tệp (Bob)** và bấm **Bật máy nhận**.
3. Trang sẽ hiện địa chỉ IP và dấu vân tay khóa của Bob. Gửi hai thông tin này cho Alice.
   - Bỏ qua địa chỉ `192.168.56.1`: đó là card mạng ảo của VirtualBox.

**Trên máy Alice:**

4. Chạy giao diện như phần trên.
5. Mở trang **Gửi tệp (Alice)**.
6. Chọn tệp, nhập IP của Bob rồi bấm **Gửi cho Bob**.
   - Ô vân tay của Bob có thể để trống, nhưng như vậy là không xác thực khóa.
7. Bạn sẽ thấy khung xanh `Bob trả lời: CHAP NHAN: ...`.
8. Trên máy Bob, tệp hiện ở mục **Tệp đã nhận** sau khoảng 2 giây. Bấm **Tải về** để lưu tệp.

**Lưu ý:**
- Muốn thử trên một máy thì làm cả hai trang trên cùng một giao diện, với IP Bob là `127.0.0.1`.
- Máy nhận chạy tới khi tắt giao diện. Muốn đổi vân tay khóa ký của Alice thì tắt giao diện (Ctrl+C), chạy lại, rồi bật lại máy nhận.
- Chuẩn bị mạng, tường lửa và ý nghĩa dấu vân tay: xem `Network/README.md`.
