# Báo cáo Kiểm chứng Dữ liệu Thực nghiệm Runtime (Chapter 13 Labs)

## 1. Tổng quan Nghiệm thu & Phạm vi Đánh giá
- **Thời điểm kết xuất (generated_at):** Thời gian thực hiện kiểm định cục bộ (ISO-8601).
- **Trạng thái thực nghiệm chung (overall_runtime_status):** `partial_runtime_coverage`
- **Kết quả bộ kiểm thử assert (assertions_passed):** `True` (Tất cả điều kiện kiểm định dữ liệu kỹ thuật đều đạt 100%).
- **Môi trường thực nghiệm:** Máy ảo Windows 10 x64 độc lập.
- **Dấu vết băm SHA-256 các tệp bằng chứng (`artifacts/verification/`):**
  - `verify-runtime.csv`: `29ce7926cdf57d692b1cf39d130157ff173c97219b2fdd521cb10169bf0880ac`
  - `lab01-exit.json`: `dbb5c8c0452ffcab5e94d6e4777483d193272b3b42ab99f8af338eb9da1c3142`
  - `lab02-files2.json`: `ec08704ec657bfe9521d0bb30d48212862932b0f0333049195cc7c113cd463f5`
  - `lab03-run.json`: `d2b4ce8ae22935f131d3ea064e255c36117c68a480079e3a4f3a873ce37c2b9f`
  - `http-o.jsonl`: `53bee2e7eda235ba681984dd35d1e4236f338af448154c3247ca19d61ff1652a`
  - `tcp8910.jsonl`: `da103bf9e64fc51da3b5bcb8e7c4298e9561de7b13b301541e0fe76c82c8684d`
  - `temp00ca77b9.enc`: `a866891a4a26733327f73afb70c53dccaed23946ba1d678ad8dd85a92754eba1`
  - `recovered-verify.bmp`: `5461422 bytes` (1507x906, 32bpp)
  - `lab03-verify-cipher.bin`: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (0 bytes)

---

## 2. Chi tiết Kỹ thuật và Đối chiếu Từng Mẫu Malware

### 2.1. Lab13-01.exe (Beaconing HTTP & Trễ Thoát Tiến Trình)
- **PID theo dõi:** `4992`
- **Cơ chế mã hóa & Kiến trúc thoát (Static & Disassembly):**
  - Resource101 chứa domain được giải mã bằng XOR `0x3B`. Hostname là dữ liệu khác, được lấy12byte đầu rồi Base64 chuẩn; **không XOR hostname**. Alphabet mẫu01: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`.
  - Sau lời gọi beacon, main **luôn** thực hiện `Sleep(30000)` (`0x7530` ms), bất kể cờ phản hồi. Sau khi ngủ, main mới xét cờ từ phép so sánh `Buffer[0]=='o'`.
  - Khi kết thúc khoảng thời gian chờ, hàm `_main` gọi `WSACleanup()` để giải phóng tài nguyên Winsock rồi thực hiện câu lệnh `return 0;`. Tiến trình kết thúc thông qua CRT runtime exit (`Exit Status: 0`), **không gọi trực tiếp API `ExitProcess`** trong hàm `_main`.
- **Dữ liệu đối chiếu Runtime (Procmon CSV):**
  - **Dòng 2647:** `8:36:59.0024594 PM` | `TCP Receive` | `Length: 137, seqnum: 0, connid: 0`
  - **Dòng 2718:** `8:37:29.0234778 PM` | `Process Exit` | `Exit Status: 0, User Time: 0.0156250s, Kernel Time: 0.0156250s`
  - **Thời gian trễ thực tế:**
    $$\Delta t = 20:37:29.0234778 - 20:36:59.0024594 = 30.0210184\text{ giây}$$
  - Khoảng đo phù hợp `Sleep(30000)` cộng thời gian xử lý/lập lịch; không có trace để quy riêng phần chênh21ms cho scheduler.
- **Trạng thái xác thực:** `VERIFIED_PASS`

---

### 2.2. Lab13-02.exe (Chụp Màn hình Desktop & Chu kỳ Ghi Đĩa)
- **PID theo dõi:** `3876`
- **Cơ chế mật mã & Vị trí ghi tệp (Static & Disassembly):**
  - Thuật toán mã hóa hình ảnh bitmap chụp được là **biến thể phái sinh từ Rabbit stream cipher** (sử dụng hằng số mở rộng trạng thái `0x4D34D35D`, cấu trúc trạng thái nội bộ 68 bytes). **Tuyệt đối không phải simple XOR**.
  - Mã độc tạo tên tệp theo quy luật `tempXXXX` và ghi trực tiếp vào **thư mục làm việc hiện tại (Current Working Directory - CWD)** tại `C:\Lab13Analysis\verify\captures\`, **không ghi vào thư mục tạm của hệ thống (%TEMP%)**.
  - Trong mỗi chu kỳ vòng lặp, mã độc thực thi **2 lệnh gọi `Sleep(5000)` liên tiếp**: một lần trước khi chụp (`0x004018fa`) và một lần sau khi chụp/ghi tệp (`0x0040190a`), thiết lập chu kỳ tối thiểu $\ge 10$ giây giữa 2 lần chụp liên tiếp.
- **Dữ liệu đối chiếu Runtime (Procmon CSV & Disk Files):**
  - **Dòng 3271:** `8:39:31.7045111 PM` | `WriteFile` | `C:\Lab13Analysis\verify\captures\temp00ca77b9` | `Length: 5,461,422`
  - **Dòng 3274:** `8:39:41.9263907 PM` | `WriteFile` | `C:\Lab13Analysis\verify\captures\temp00ca9fb4` | `Length: 5,461,422`
  - **Khoảng cách thời gian ghi đĩa:**
    $$\Delta t = 20:39:41.9263907 - 20:39:31.7045111 = 10.2218796\text{ giây}$$
  - Khoảng chênh lệch $\approx 0.222\text{ giây}$ vượt trên 10 giây ngủ là **độ trễ tổng hợp** bao gồm: thời gian chụp Win32 GDI BitBlt, chi phí tính toán Rabbit cipher trên 5.4MB dữ liệu, thời gian I/O ghi đĩa và scheduling hệ thống. **Không có bằng chứng thực nghiệm nào chứng minh độ trễ này chỉ do riêng GDI tạo ra**.
  - **Đối chiếu tệp khôi phục:** Tệp `temp00ca77b9.enc` được giải mã thành công ra `recovered-verify.bmp` với kích thước đúng 5,461,422 bytes, cấu trúc chuẩn bitmap 1507x906, 32bpp (khác với BMP lượt02 đầu 1505x903 5,436,114B).
- **Trạng thái xác thực:** `VERIFIED_PASS`

---

### 2.3. Lab13-03.exe (Reverse Shell & Kiểm Thử Phản Hồi C2)
- **PID theo dõi:** `5672`
- **Kiến trúc mật mã (Static & Disassembly):**
  - Chiều nhận lệnh (Inbound): Sử dụng **Custom Base64** với bảng ký tự hoán vị tùy biến (shift-2 alphabet).
  - Chiều gửi dữ liệu (Outbound): Sử dụng mã hóa khối **AES-128-CBC** được cài trong các hàm của mẫu (kết luận tĩnh, không phải Windows CryptoAPI).
  - **Không sử dụng shellcode, không sử dụng Substituted XOR**.
- **Dữ liệu đối chiếu Runtime (Procmon CSV & Network Telemetry):**
  - **Dòng 4237:** `8:40:41.2600126 PM` | `Process Create` | Sinh tiến trình con `cmd.exe` PID `1296` (tiến trình cha `Lab13-03.exe` PID `5672`).
  - **Dòng 4650:** `8:40:43.4519532 PM` | `TCP Receive` | `Length: 28` | Nhận payload encoding trên wire `BYPqdaDOSWKzO19YTXLLTmnHTC0M`.
  - **Đánh giá Inbound:** Chuỗi 28 bytes này **chỉ được ghi nhận là network payload nhận trên tầng mạng (TCP socket)**. Trong dữ liệu runtime độc lập hiện có, **không có bằng chứng xác nhận mã độc đã giải mã thành công hay `cmd.exe` đã thực thi lệnh `echo LAB13_VERIFIED`**.
  - **Đánh giá Outbound Echo Test:**
    - Tệp phản hồi `lab03-verify-cipher.bin` ghi nhận kích thước `0 bytes`.
    - Đây là **kiểm thử echo thất bại (FAILED echo test)**, không được coi là PASS hay expected PASS.
    - **Nguyên nhân:** Đánh giá là **UNKNOWN**. Giả thuyết về bộ đệm 4096 bytes của pipe vô danh trên Windows hay thời gian flush socket chưa được chứng minh bằng thực nghiệm độc lập.
- **Trạng thái xác thực:** `PARTIAL_COVERAGE` (Xác thực được cấu trúc tiến trình con và socket TCP 8910; chưa hoàn tất kiểm chứng phản hồi outbound mã hóa).

---

## 3. Bảng Tổng Hợp Kiểm Định Runtime

| Hạng mục | Cơ chế kỹ thuật chuẩn | Bằng chứng Procmon / Telemetry | Kết quả thực nghiệm |
| :--- | :--- | :--- | :---: |
| **Lab13-01 Encoding** | Standard Base64 sau XOR 0x3B | HTTP GET `/REVTS1RPUC1WNVZD/` | **VERIFIED** |
| **Lab13-01 Exit** | `Sleep(30000)`, `WSACleanup()`, `return 0` | Dòng 2647 $\rightarrow$ Dòng 2718 (30.021s) | **VERIFIED** |
| **Lab13-02 Cipher** | Rabbit-derived cipher (hằng số 0x4D34D35D) | Mã hóa khối ảnh 5,461,422 bytes | **VERIFIED** |
| **Lab13-02 Location** | Ghi tệp tại CWD (`captures\\tempXXXX`) | Dòng 3271 & 3274 ghi vào CWD | **VERIFIED** |
| **Lab13-02 Interval** | 2 lần `Sleep(5000)` $\ge 10$s + overhead tổng hợp | Dòng 3271 $\rightarrow$ Dòng 3274 (10.222s) | **VERIFIED** |
| **Lab13-02 Recovery** | BMP 1507x906 32bpp (5,461,422B) | `recovered-verify.bmp` đã kiểm định | **VERIFIED** |
| **Lab13-03 Inbound** | Custom Base64 (shift alphabet) | Dòng 4650 nhận 28B payload qua wire | **NETWORK_ONLY** |
| **Lab13-03 Outbound** | AES-128-CBC (cài trong mẫu, tĩnh) | `lab03-verify-cipher.bin` = 0B | **FAILED_ECHO** |
| **Lab13-03 Child Proc** | Spawn `cmd.exe` PID 1296 | Dòng 4237 (`Process Create`) | **VERIFIED** |

---
*Báo cáo được đồng bộ tự động với `analysis/verify_runtime.py` và `analysis/runtime-verification.json`.*
