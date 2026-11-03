# Hồ sơ kiểm chứng bổ sung — kết quả, không phải cam kết

Ngày 02/11/2026; mẫu chỉ thực thi trong guest Win10 VMware.
NIC Disconnected, observer80/8910 bind127.0.0.1; preflight ghi Burp8080 bind:: (wildcard IPv6). Shared folder bật/ghi được
trong lượt này; không tuyên bố air-gap.

## Lab13-01
- IDA: main Sleep(500), beacon, Sleep(30000), kiểm tra cờ rồi WSACleanup/return0.
- IDA: Buffer[0]==111; Burp ảnh32: body đúng `o`, Content-Length1.
- Procmon ảnh37: PID4992 Exit Status0 lúc20:37:29.0234778.
- JSON forced=false; CSV TCP Receive20:36:59.0024594.
- Khoảng từ TCP Receive tới Exit:30.0210184s. Không có hành vi tự xóa.

## Lab13-02
- IDA ảnh33: `Sleep(5000); sub_401851(); Sleep(5000);` lặp.
- IDA ảnh34: state68B memset zero; mã máy/decoder xác định biến thể Rabbit.
- Procmon ảnh38: PID3876 WriteFile20:39:31.7045111 và20:39:41.9263907.
- Mỗi tệp5.461.422B; khoảng đo10.2218796s, phù hợp >=10s+thời gian xử lý.
- `temp00ca77b9.enc` giải mã thành `recovered-verify.bmp`,1507×906,32bpp.
- Lượt đầu khác độ phân giải:1505×903,5.436.114B.
- Mẫu02 được dừng cưỡng bức sau cửa sổ kiểm tra; không phải tự thoát.

## Lab13-03
- Tĩnh: inbound Custom Base64, outbound AES-128-CBC, hai hướng khác nhau.
- Fixed marker plaintext21B: `echo LAB13_VERIFIED\r\n`.
- Standard Base64: `ZWNobyBMQUIxM19WRVJJRklFRA0K`.
- Custom Base64: `BYPqdaDOSWKzO19YTXLLTmnHTC0M` (28B).
- Đối chiếu encoding thực hiện ngoại tuyến, không chứng minh decoder malware đã chạy.
- Runtime PID5672: TCP8910, cmd.exe PID1296, TCP Receive28B.
- Observer thu0B outbound. Test marker **chưa xác nhận thành công**.
- Chưa có API trace/breakpoint chứng minh ghi stdin, thực thi echo hoặc AES đã chạy.
- Nguyên nhân0B chưa xác định; buffering4096B chỉ là giả thuyết, không kết luận.

## Độ phủ ảnh GUI
36ảnh toàn màn hình thật. Các phần còn thiếu GUI: raw Resource101, toàn bộ
alphabet mẫu01 trong cùng khung hình, Burp Decoder hostname, hằng số Rabbit ở hex.
Kết luận tĩnh tương ứng có raw export/đối chiếu ngoại tuyến, không thay ảnh chưa có.

## Tệp đối chiếu
`artifacts/verification/verify-all.pml`, `verify-runtime.csv`, JSON/JSONL.
`analysis/verify_runtime.py`, `runtime-verification.json`, `verification-matrix.json`.
Không có PCAP; kiểm thử offline không thay kiểm chứng malware live.

## Kết thúc
Mẫu và observer đã dừng; hosts/proxy khôi phục; controller đã dừng.
Guest thử ghi share gốc bị Access denied. RuntimeConfig và VMX share tạm
present=false/enabled=false/writeAccess=false; guest vẫn thấy cache đường
Lab13Transfer. Đọc `final-isolation.json` và `vm-final-*.txt`, không tuyên bố
đường dẫn cache đã biến mất. NIC tiếp tục Disconnected/startConnected=false.
Sau yêu cầu chạy ẩn, không có thêm thao tác màn hình/chuột hay ảnh GUI mới.
