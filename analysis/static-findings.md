# BÁO CÁO PHÂN TÍCH TĨNH CHÍNH XÁC (STATIC VERIFIED FINDINGS)
**Phạm vi**: Practical Malware Analysis Labs - Chapter 13 (Chapter_13L)  
**Mẫu phân tích**: Lab13-01.exe, Lab13-02.exe, Lab13-03.exe  
**Phương pháp**: Phân tích PE, Disassembly bằng Capstone Engine, đối chiếu IAT và Crypto Constants trực tiếp từ byte nhị phân. Không chạy malware trên host.

---

## 1. LAB13-01 (Lab13-01.exe)
- **Kích thước**: 32,768 bytes | **MD5**: `a9a2734d080e3ae0f5ada35e878da7c8` | **SHA256**: `71a295247ba7419f9f9dea8098e6867182bb80f53c98eb0f59192a6557a51249`
- **Entry Point**: `0x00401681` | **ImageBase**: `0x00400000`

### 1.1. Cơ chế giải mã C2 Domain (Resource XOR)
- **Vị trí**: Resource `.rsrc` -> `RT_RCDATA` -> ID `101`, kích thước 32 bytes (RVA `0x00008060`, VA `0x00408060`).
- **Ciphertext (32 bytes)**:
  `4c 4c 4c 15 4b 49 5a 58 4f 52 58 5a 57 56 5a 57 4c 5a 49 5e 5a 55 5a 57 42 48 52 48 15 58 54 56`
- **Hàm giải mã**: `sub_401190` (VA `0x00401190`).
  * Thuật toán: Single-byte XOR với khóa cố định `0x3B`.
  * Mã máy: `0x4011b6: mov al, [edx]; 0x4011b8: xor eax, 0x3b; 0x4011c1: mov [ecx], al`.
- **Plaintext sau giải mã**: `www.practicalmalwareanalysis.com`

### 1.2. Thu thập & Mã hóa Hostname
- **Thu thập**: Tại `sub_4011c9` gọi `gethostname` (`0x0040146a` -> `0x004050d8`), bộ đệm 256 bytes (`push 0x100`).
- **Cắt ngắn**: Lấy tối đa **12 ký tự đầu tiên** (`push 0xc` -> gọi `_strncpy` tại `0x00401216`), đặt null-byte kết thúc tại vị trí 12 (`mov byte ptr [ebp-0xc], 0`).
- **Mã hóa Base64**:
  * Hàm `sub_4010b1`: Chia chuỗi 12-byte thành các khối 3-byte.
  * Hàm `sub_401000`: Tính toán chỉ số 6-bit và tra cứu trên bảng Base64 chuẩn.
  * Bảng Base64 tại VA `0x004050e8`:
    `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

### 1.3. Giao thức Mạng & Lệnh điều khiển
- **URL beacon**: Format `http://%s/%s/` (VA `0x0040603c`) -> `http://www.practicalmalwareanalysis.com/<base64_hostname>/`
- **WinINet**: User-Agent `Mozilla/4.0` (VA `0x00406030`), `InternetOpenA` (`0x004050c0`), `InternetOpenUrlA` (`0x004050c4`), `InternetReadFile` (`0x004050cc`).
- **Cơ chế phản hồi từ C2**:
  * Đọc byte đầu tiên của response từ server: so sánh với `0x6F` (ký tự ASCII `'o'`).
  * Mỗi vòng ngủ 500 ms trước beacon, rồi gọi `Sleep(30000)` vô điều kiện sau beacon. Phép kiểm tra kết quả chỉ diễn ra sau giấc ngủ 30 giây này.
  * Nếu byte đầu == `'o'`: Hàm `sub_4011c9` trả về `1`; sau giấc ngủ cuối, main ngắt vòng lặp, gọi `WSACleanup` và **thoát chương trình (Exit)**.
  * Nếu byte đầu != `'o'` hoặc lỗi mạng: sau giấc ngủ, main quay lại lượt beacon tiếp theo.

---

## 2. LAB13-02 (Lab13-02.exe)
- **Kích thước**: 32,768 bytes | **MD5**: `b65c4d7cbc4069ddbff665370201e588` | **SHA256**: `598f21f1e6f4d5829ba8cfba19d361e09de510493df8472a605f46dbf7927030`
- **Entry Point**: `0x00401d3a` | **ImageBase**: `0x00400000`

### 2.1. Chụp màn hình (Screen Spyware)
- **Hàm `sub_401070`**:
  * Lấy DC màn hình desktop: `GetDesktopWindow` (`0x00406004`), `GetDC` (`0x00406008`).
  * Lấy kích thước: `GetSystemMetrics(SM_CXSCREEN = 0)`, `GetSystemMetrics(SM_CYSCREEN = 1)`.
  * Tạo bộ đệm tương thích: `CreateCompatibleDC` (`0x00406010`), `CreateCompatibleBitmap` (`0x00406014`).
  * Chụp toàn bộ điểm ảnh: `BitBlt` (`0x0040601c`) với raster operation `0x00CC0020` (`SRCCOPY`).
  * Trích xuất mảng DIB: `GetDIBits` (`0x00406020`) tạo cấu trúc file ảnh Bitmap (`.bmp`).

### 2.2. Thuật toán mã hóa Rabbit Stream Cipher
- **Hàm thực thi**: `sub_40181f` gọi `sub_401739` và `sub_4012dd`.
- **Hằng số ma thuật (Magic Constants) trong Binary**:
  * Lệnh `lea` tại VA `0x40131b`, `0x40137b`, `0x4013db`: `0x4D34D35D` (RFC 4503 dùng `0x4D34D34D`).
  * Lệnh `lea` tại VA `0x40133b`, `0x40139b`: `-0x2cb2cb2d` (tương đương `0xD34D34D3`).
  * Lệnh tại VA `0x40135b`, `0x4013bb`: `0x34D34D34`.
- **Trạng thái & Khóa**: Context `0x44` bytes được `memset` toàn bộ về `0x00`; không key schedule hoặc warmup.
- **Mã hóa**: Xử lý XOR keystream theo từng block 16 bytes (`add eax, 0x10`). Do bản chất đối xứng của Rabbit XOR stream, cùng thuật toán áp dụng lên ciphertext sẽ giải mã trở lại file Bitmap gốc.

### 2.3. Tệp tin tạo ra
- **Định dạng tên tệp**: `temp%08x` (tại VA `0x00407030`).
- **Giá trị biến thiên**: Tham số lấy từ API `GetTickCount` (`0x00406038`) tại thời điểm chụp, ví dụ: `temp000bc12a`.
- **Ghi tệp**: Hàm `sub_401000` gọi `CreateFileA` (`0x0040604c`, `CREATE_ALWAYS`) và `WriteFile` (`0x00406050`).
- **Chu kỳ**: Vòng lặp `_main` tại `0x004018D8` gọi 2 lệnh `Sleep(5000)` (`0x1388` ms) liên tiếp: một lần trước khi chụp (`0x004018fa`) và một lần sau khi chụp (`0x0040190a`) rồi mới lặp lại. Do đó khoảng cách giữa hai lần chụp liên tiếp là $\ge 10$ giây cộng thời gian chụp GDI, mã hóa và ghi file (không phải 5 giây; lượt PID3876 đo được hai WriteFile cách10.2218796s, xem ảnh38 và runtime-verification.json).

---

## 3. LAB13-03 (Lab13-03.exe)
- **Kích thước**: 77,824 bytes | **MD5**: `98ea0fe0594f0f373d9791886a01db8c` | **SHA256**: `86054002565c929215b82615477652d24379b9119bc33ef7f41706ee7e125379`
- **Entry Point**: `0x004069bf` | **ImageBase**: `0x00400000`

### 3.1. Thiết lập C2 Socket
- **Hàm main `sub_401879`**:
  * Winsock: `WSAStartup` version 2.2 (`0x202`).
  * Socket: `WSASocketA(AF_INET = 2, SOCK_STREAM = 1, IPPROTO_TCP = 6)`.
  * C2 Domain: `www.practicalmalwareanalysis.com` (VA `0x0041221c`).
  * Cổng kết nối C2: `htons(0x22ce)` = **Cổng TCP 8910**.

### 3.2. Cấu trúc Reverse Shell đa luồng (Anonymous Pipes)
- **Hàm `sub_4015b7`**:
  * Tạo đường ống: `CreatePipe` (`0x0040c03c`) 2 lần tạo cặp read/write pipe.
  * Nhân bản handle: `DuplicateHandle` (`0x0040c038`) để chuyển hướng `hStdInput`, `hStdOutput`, `hStdError`.
  * Khởi tạo tiến trình con: `CreateProcessA` (`0x0040c02c`) gọi `cmd.exe` (chuỗi tại VA `0x004121bc`).
  * Tạo 2 luồng độc lập (`CreateThread` `0x0040c028`) để phục vụ 2 chiều giao tiếp.

### 3.3. Tách bạch chính xác Inbound vs Outbound
Bác bỏ giả thuyết mã hóa đa tầng (multi-layer) lồng ghép. Thực tế mã độc áp dụng **2 thuật toán riêng biệt cho 2 chiều**:

1. **Chiều Inbound (C2 -> Shell) - Thread `sub_40147c`**:
   - Nhận lệnh từ mạng qua Socket: `ReadFile` (`0x0040c020`).
   - Giải mã bằng **Custom Base64** tại hàm `sub_401082`.
   - Bảng ký tự Custom Base64 tại VA `0x004120a4` (Offset file `0x120a4`):
     `CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/`
     *(Bảng alphabet chuẩn bị xoay vòng sang trái 2 vị trí: AB chuyển về cuối chữ hoa, ab chuyển về cuối chữ thường)*.
   - Ghi lệnh đã giải mã vào stdin pipe của `cmd.exe`: `WriteFile` (`0x0040c01c`).

2. **Chiều Outbound (Shell -> C2) - Thread `sub_40132b`**:
   - Đọc kết quả stdout/stderr từ pipe của `cmd.exe`: `ReadFile` (`0x0040c020`).
   - Mã hóa dữ liệu bằng **AES-128-CBC**:
     * Hàm mã hóa: `sub_40352d` với context `ecx = 0x00412ef8`.
     * Sự hiện diện của bảng S-Box chuẩn AES tại VA `0x0040c908` (`63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76`).
     * Khóa AES 16 bytes tại VA `0x00412208`: `ijklmnopqrstuvwx` (ASCII 16 bytes).
     * Vector khởi tạo (IV): 16 bytes uninitialized BSS tại VA `0x00413374` (mặc định khởi tạo `0x00`).
     * CBC không chỉ được suy ra từ S-box: tại `0x4035DB` gọi XOR plaintext với feedback, `0x4035F1` gọi AES core, `0x40360D` sao chép ciphertext vào feedback `context+0x3F4`.
     * IV được nạp khi khởi tạo tại `0x401BA9`. Feedback được duy trì giữa các lần gọi outbound, không reset zero cho mỗi message. Đây là kết luận từ mã máy, chưa được kiểm chứng bằng ciphertext thực nghiệm.
   - Gửi dữ liệu mã hóa AES trực tiếp ra Socket tới C2: `WriteFile` (`0x0040c01c`).

---
*Báo cáo dựa trên phân tích nhị phân tĩnh. Phạm vi runtime riêng: Burp ghi GET loopback; Procmon ghi tệp và tạo cmd.exe; Process Hacker ghi socket Established. Không có lệnh C2 hoặc crypto runtime được xác nhận. Assembly đối chiếu CBC lưu trong `lab13-03-crypto-audit.json`.*
