# Network: gửi tệp giữa hai máy

Alice (máy gửi) và Bob (máy nhận) chạy trên hai máy khác nhau và nói chuyện qua TCP. Đăng có thể đứng giữa để tấn công.

```
Máy Alice (sender.py) ──TCP──► [máy Đăng: proxy MITM, tùy chọn] ──TCP──► Máy Bob (receiver.py, cổng 9000)
```

| Tệp | Việc |
| --- | --- |
| `mang.py` | Gửi/nhận thông điệp (4 byte độ dài + nội dung), tính dấu vân tay khóa |
| `receiver.py` | Máy Bob: đưa khóa công khai, nhận package, kiểm tra, giải mã, lưu tệp |
| `sender.py` | Máy Alice: lấy khóa của Bob, thiết lập khóa hybrid, mã hóa + ký, gửi |

Phần mật mã dùng lại code của Thắng (`hybrid_kex`) và của Tân (`seal_file`, `open_file`). Máy Bob thêm hai bước kiểm tra:
- chống phát lại bằng `message_id`;
- so dấu vân tay khóa ký của Alice.

Nếu máy báo `Python was not found`, hãy gõ `py` thay cho `python` trong mọi lệnh bên dưới.

## A. Chạy thử trên một máy

Dùng hai cửa sổ terminal: một làm Bob, một làm Alice.

1. Mở terminal thứ nhất (cửa sổ Bob).
2. Gõ lệnh sau rồi nhấn Enter để vào thư mục `P256_MLKEM768`. Thay đường dẫn bằng chỗ bạn để repo.
   ```
   cd C:\duong\dan\toi\P256_MLKEM768
   ```
3. Gõ lệnh:
   ```
   python Network/receiver.py
   ```
4. Bạn sẽ thấy các dòng `Bob dang cho tai: ...`, `Dau van tay khoa cua Bob: xxxx xxxx xxxx xxxx`, một dòng `CANH BAO` và `Nhan Ctrl+C de dung.` Bob đang chờ, cứ để cửa sổ này mở.
5. Nếu Windows hiện hộp thoại tường lửa, tick **Private networks** rồi bấm **Allow access**.
6. Mở terminal thứ hai (cửa sổ Alice). Trong VS Code, bấm dấu **+** ở khung Terminal.
7. Gõ lại lệnh `cd` như bước 2.
8. Gõ lệnh:
   ```
   python Network/sender.py 127.0.0.1 test.txt
   ```
   `127.0.0.1` nghĩa là "chính máy này".
9. Cửa sổ Alice sẽ hiện `Bob tra loi: CHAP NHAN: da nhan test.txt (26 byte)` và một dòng thời gian. Cửa sổ Bob hiện `[127.0.0.1] CHAP NHAN: ...`.
10. Tệp giải mã được nằm ở `Network/nhan_duoc/test.txt`. 📷 *Chụp cả hai cửa sổ cho báo cáo.*
11. Muốn tắt Bob thì bấm vào cửa sổ Bob và nhấn **Ctrl+C**.

## B. Chạy trên hai máy thật

**Chuẩn bị:**
- Cả hai máy đều có thư mục `P256_MLKEM768` và đã cài thư viện bằng `python -m pip install cryptography`.
- Hai máy phải vào **cùng một mạng Wi-Fi**. Wi-Fi trường thường chặn các máy nói chuyện với nhau; khi đó hãy phát Wi-Fi từ điện thoại rồi cho cả hai máy vào.

**Trên máy Bob:**

1. Mở terminal và `cd` vào thư mục `P256_MLKEM768`.
2. Gõ lệnh:
   ```
   python Network/receiver.py
   ```
3. Nhìn dòng `Bob dang cho tai:` và ghi lại địa chỉ của mạng Wi-Fi, thường có dạng `192.168.x.x` hoặc `10.x.x.x`.
   - Bỏ qua `192.168.56.1`: đó là card mạng ảo của VirtualBox.
   - Nếu không chắc địa chỉ nào đúng, gõ `ipconfig` ở một terminal khác và xem mục **Wireless LAN adapter Wi-Fi** → **IPv4 Address**.
4. Windows hiện hộp thoại tường lửa thì tick **Private networks**, bấm **Allow access**. Nếu Wi-Fi đang để chế độ Public thì tick thêm **Public networks**.

**Trên máy Alice:**

5. Mở terminal và `cd` vào thư mục `P256_MLKEM768`.
6. Gõ lệnh sau, thay `192.168.1.20` bằng địa chỉ ghi ở bước 3 và `test.txt` bằng tệp muốn gửi:
   ```
   python Network/sender.py 192.168.1.20 test.txt
   ```
7. Bạn sẽ thấy `Bob tra loi: CHAP NHAN: ...`. 📷 *Chụp màn hình hai máy.*

**Nếu lỗi:**

| Lỗi ở máy Alice | Nguyên nhân thường gặp |
| --- | --- |
| `TimeoutError` hoặc `ConnectionRefusedError` | Gõ sai IP, Bob chưa chạy, tường lửa máy Bob chặn, hoặc Wi-Fi chặn các máy nói chuyện với nhau |
| `ModuleNotFoundError: No module named 'cryptography'` | Chưa cài thư viện (xem phần chuẩn bị) |

## C. Bật xác thực bằng dấu vân tay (chống MITM)

Khi chưa bật, Alice tin mọi khóa công khai nhận qua mạng. Kẻ đứng giữa có thể đưa khóa của hắn thay cho khóa của Bob và đọc được tệp. Dấu vân tay là 16 ký tự đầu của SHA-256 của khóa. Hai bên đọc nó cho nhau qua **một kênh khác** (gọi điện, nhắn tin, gặp trực tiếp), không qua mạng đang dùng để gửi tệp.

1. Trên máy Bob, chép dòng `Dau van tay khoa cua Bob: ...` rồi nhắn cho Alice.
2. Trên máy Alice, gửi tệp kèm vân tay đó:
   ```
   python Network/sender.py 192.168.1.20 test.txt --van-tay-bob "4890 a50a 8f64 8210"
   ```
   Bạn sẽ thấy `Khoa cua Bob: ... (da xac thuc)`. Nếu khóa nhận được không khớp, Alice in `DUNG: ...` và **không gửi tệp**.
3. Trên máy Alice, chép dòng `Dau van tay khoa ky cua Alice: ...` rồi nhắn cho Bob.
4. Trên máy Bob, nhấn **Ctrl+C** để tắt, rồi chạy lại kèm vân tay của Alice:
   ```
   python Network/receiver.py --van-tay-alice "xxxx xxxx xxxx xxxx"
   ```
   Dòng `CANH BAO` sẽ không còn. Từ giờ Bob từ chối mọi package ký bằng khóa không phải của Alice.

Hai dấu vân tay không đổi giữa các lần chạy, vì mỗi máy lưu khóa của mình trong `Network/khoa/`. Thư mục này nằm trong `.gitignore`. **Không gửi nó cho ai**, vì trong đó là khóa riêng.

## D. Cho Đăng: tấn công qua mạng

`attack_lab.py` vẫn chạy như cũ vì code của Thắng và Tân không bị sửa.

Muốn tấn công qua mạng thì viết một proxy:
- Proxy chạy trên máy Đăng, mở một cổng (ví dụ 9001).
- Alice gõ IP máy Đăng thay cho IP máy Bob: `python Network/sender.py <IP Đăng> test.txt --port 9001`.
- Proxy kết nối tới Bob và chuyển tiếp từng thông điệp bằng `gui()` / `nhan()` trong `mang.py`. Trên đường đi, nó sửa package bằng `dec_package` / `enc_package` giống `attack_lab.py`.

Mỗi lần gửi tệp là một kết nối TCP gồm 5 thông điệp, theo thứ tự:

| # | Chiều | Nội dung |
| --- | --- | --- |
| 1 | Bob → Alice | Khóa công khai ECDH P-256 (33 byte) |
| 2 | Bob → Alice | Khóa công khai ML-KEM-768 (1184 byte) |
| 3 | Alice → Bob | Khóa công khai kiểm tra chữ ký của Alice (PEM) |
| 4 | Alice → Bob | Package (JSON) |
| 5 | Bob → Alice | Kết quả: `CHAP NHAN: ...` hoặc `TU CHOI: ...` |

Kết quả dưới đây đã được kiểm thử bằng một proxy giả lập trên một máy:

| Tấn công | Chưa bật vân tay | Đã bật vân tay |
| --- | --- | --- |
| Sửa 1 byte ciphertext | Bob từ chối: `INVALID_SIGNATURE` | Như bên trái |
| Gửi lại nguyên package cũ (replay) | Bob từ chối: `message_id ... da nhan roi` | Như bên trái |
| Thay khóa công khai của Bob, giải mã tệp, mã hóa lại cho Bob và ký bằng khóa của kẻ tấn công | **Tấn công thành công**: kẻ tấn công đọc được tệp, Bob vẫn chấp nhận | Alice `DUNG` trước khi gửi (`--van-tay-bob`); Bob từ chối khóa ký lạ (`--van-tay-alice`) |

Replay trong `attack_lab.py` vẫn ra `[LO HONG]` vì demo đó gọi thẳng `open_file`, mà `open_file` không nhớ `message_id`. Máy Bob ở đây có thêm bước nhớ `message_id`, nên chặn được.
