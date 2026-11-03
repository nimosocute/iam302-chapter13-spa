# CHẨN ĐOÁN KỸ THUẬT: MẪU LAB13-03.EXE (I/O & PIPE REVERSE SHELL)

**Tài liệu tham chiếu**: `D:\FPT University\FA26\IAM302\share\Lab13Transfer\Lab13-03.exe.bin`  
**Phương pháp**: Phân tích tĩnh mã máy (`pefile` / `capstone`), đối chiếu nhật ký mạng cô lập (Procmon / C2 Listener).  
**Giới hạn**: Không khẳng định hoàn thành toàn bộ bài lab. Không thực thi mẫu trên host.

---

## 1. DỮ KIỆN ĐÃ XÁC THỰC (VERIFIED FACTS)

- **Khởi tạo & Tiến trình**: Trên máy ảo Win10, mẫu `Lab13-03.exe` (PID 5672) kết nối loopback TCP tới `127.0.0.1:8910` và gọi `CreateProcessA` tạo tiến trình con `cmd.exe` (PID 1296).
- **Gói tin Inbound (28B)**: C2 listener gửi chuỗi Custom Base64 `BYPqdaDOSWKzO19YTXLLTmnHTC0M` (28 bytes). Procmon xác nhận sự kiện `TCP Receive` đúng 28 bytes lúc 8:40:43.45 PM trên PID 5672.
- **Ánh xạ giải mã tĩnh (Offline Mapping Only)**: Phân tích thuật toán Custom Base64 (`sub_401082`, bảng mã dịch 2 ký tự bắt đầu từ `'C'`) xác nhận chuỗi 28B trên ánh xạ tĩnh ra plaintext `echo LAB13_VERIFIED\r\n` (21B plaintext). Đây là lệnh có chủ đích, không phải dữ liệu rác hay bắt tay ngẫu nhiên.
- **Quan sát Outbound**: Phía C2 listener ghi nhận **0 byte** gửi ra (không có banner, không có phản hồi mã hóa AES). Snapshot sau4s ghi nhận cả hai tiến trình. CSV ghi cả hai Process Exit0 lúc20:40:59.33, gần thời điểm listener kết thúc; không suy ra vị trí lệnh đang chờ.

---

## 2. RANH GIỚI MÃ MÁY TĨNH (STATIC BINARY BOUNDARIES)

- `main` (`0x00401879`): Tạo socket non-overlapped `WSASocketA` (`0x004018D1`), kết nối TCP (`0x00401952`), nạp khóa AES `ijklmnopqrstuvwx` (`0x00401895`), chuyển quyền cho `sub_4015B7` (`0x0040199D`).
- `sub_4015B7`:
  * Tạo Pipe 1 (`0x00401609`, hRead=`[ebp-0x30]`, hWrite=`[ebp-0x48]`).
  * Tạo Pipe 2 (`0x0040161D`, hRead=`[ebp-0x5C]`, hWrite=`[ebp-0x38]`).
  * Gán `STARTUPINFOA`: `hStdInput = Pipe 2 Read`, `hStdOutput = Pipe 1 Write`, `hStdError = Pipe 1 Write`.
  * `CreateProcessA` (`0x0040177B`) tạo `cmd.exe` với `STARTF_USESTDHANDLES`.
  * Tạo luồng Inbound `sub_40147C` (`0x00401807`): đọc socket qua `ReadFile` (`0x004014ED`), giải mã `sub_401082` (`0x0040154E`), ghi vào Pipe 2 write qua `WriteFile` (`0x00401580`).
  * Tạo luồng Outbound `sub_40132B` (`0x0040184B`): đọc Pipe 1 read qua `ReadFile` (`0x004013AB`), mã hóa AES-128-CBC `sub_40352D` (`0x0040142E`), ghi ra socket qua `WriteFile` (`0x00401454`).
  * Luồng chính gọi `WaitForSingleObject(pi.hProcess, INFINITE)` (`0x0040186D`).

---

## 3. ĐÁNH GIÁ NGUYÊN NHÂN & GIỚI HẠN XÁC MINH

- **Trạng thái thực thi runtime chưa được chứng minh**: Hiện chưa có vết API động (API tracing/hooking) bên trong PID 5672 và PID 1296. Không có bằng chứng để biết `cmd.exe` đã thực thi lệnh hay chưa, cũng như không thể biết liệu `ReadFile` trên pipe có bị chặn hay nhánh mã hóa AES có được chạm tới hay không.
- **Hiện tượng 0B Outbound**: Việc listener nhận 0 byte chỉ phản ánh kết quả quan sát thụ động từ mạng (no observed bytes). Nguyên nhân chính xác dẫn đến việc không có byte nào phát sinh ra socket hiện **CHƯA RÕ (CAUSE UNKNOWN)**.
- **Giả thuyết đệm khối 4096B**: Nhận định cho rằng CRT của `cmd.exe` chuyển sang chế độ full-buffering 4096B chỉ là một giả thuyết suy diễn kỹ thuật, **KHÔNG PHẢI LÀ SỰ THẬT ĐÃ ĐƯỢC XÁC MINH**, không được coi là nguyên nhân gốc (root cause).
