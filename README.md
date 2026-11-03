# Chapter_13L — SPA phân tích malware

## Mở bài
1. Giải nén toàn bộ ZIP, giữ cấu trúc thư mục.
2. Mở `index.html` bằng Edge/Chrome; không cần server hoặc Internet.
3. Đọc lần lượt **Bắt đầu → Lab13-01 → Lab13-02 → Lab13-03 → Kết luận chung & IOC**.
   Mỗi bước có giải thích, ảnh ngay bên dưới, hướng dẫn đọc và kết luận.
   Không cần chuyển sang chỉ mục ảnh để tìm bằng chứng.
4. Nhấn ảnh để xem nguyên khung; Escape đóng ảnh và trả focus về nút vừa mở.
   “Chỉ mục ảnh” chỉ để tra cứu thêm; mỗi ảnh có liên kết về đúng đoạn giải thích.
5. Chuẩn bị video theo `TRANSCRIPT.md`. Lời nói từng bước cũng có sẵn trong SPA,
   ở mục thu gọn “Lời thuyết minh cho bước này”. Khi quay chỉ cần hiển thị SPA,
   chuyển tab/đọc theo thứ tự; không yêu cầu mở lại công cụ hay chạy lại mẫu.

Folder13 theo số dư đã cung cấp. Chưa điền tên/MSSV vì chưa được cung cấp.

## Kết quả
| Mẫu | Cơ chế tĩnh | Đã quan sát |
|---|---|---|
| Lab13-01.exe | Resource101 XOR0x3B, hostname12byte Base64 chuẩn, WinINet GET; Sleep500/30000 | Burp request và body`o`; PID4992 tự thoát Exit0, không bị kill; TCP Receive tới Exit30.0210184s |
| Lab13-02.exe | GDI capture; Rabbit biến thể, state68B zero; hai Sleep5000 | PID3876 hai WriteFile cách10.2218796s, mỗi tệp5.461.422B; giải mã BMP1507×906,32bpp |
| Lab13-03.exe | TCP8910; pipe tới cmd.exe; inbound Custom Base64, outbound AES128-CBC | cmd.exe child, TCP Established, nhận28B fixed marker; outbound0B, chưa xác nhận echo/AES runtime |

Lượt02 đầu:5.436.114B,BMP1505×903, HxD/Paint đã mở (ảnh19–21).
Lượt bổ sung khác độ phân giải, không phải kích thước tệp cố định của malware.
Mẫu02 được dừng cưỡng bức sau cửa sổ quan sát.
Base64 là encoding, không bảo mật; AES và Custom Base64 mẫu03 thuộc hai hướng riêng.

## Bằng chứng thật
- **36 PNG toàn màn hình2560×1600**: VMware, IDA Pro, Burp Suite Professional,
  Procmon, Process Hacker, HxD, HashMyFiles, Paint. Không crop/ghép/thêm chữ.
- Burp được mở từ `C:\Users\bachdeptrai\Desktop\Burp Suite Pro.lnk`; giữ phiên
  Professional có sẵn, không mở từ launcher khác.
- Ảnh29 tên file chứa response-o nhưng chỉ thấy đầu hàm hostname/WinINet;
  ảnh31 mới hiển thị `Buffer[0]==111`. Ảnh30 chỉ hiển thị một phần alphabet.
- Có hỗ trợ tự động điều khiển/trích xuất. Ảnh chứng minh trạng thái công cụ,
  không tự chứng minh sinh viên thao tác thủ công hay danh tính.
- Sau yêu cầu chạy ẩn: chỉ xử lý nền/ngoại tuyến, không điều khiển chuột/màn hình,
  không tạo thêm ảnh GUI mới.
- Chưa có ảnh raw Resource101, Burp Decoder hostname hoặc Rabbit hằng số hex.
  Raw export/kiểm tra offline không được gọi là ảnh GUI đã có.

## Hồ sơ đối chiếu
| Vị trí | Nội dung |
|---|---|
| `report-data.js` | Cơ chế, IOC,36chú thích ảnh, giới hạn |
| `TRANSCRIPT.md` | Lời thuyết minh theo đúng 20 bước trên SPA, ghi rõ tab và ảnh cần hiển thị |
| `evidence/` | 36ảnh gốc; số01/17 bị loại, lưu ngoài gói |
| `analysis/evidence-catalog.json`, `screenshot-provenance.json` | Mô tả, SHA256, kích thước ảnh gốc |
| `analysis/Lab13-01-ida.json`, `Lab13-02-ida.json` | Assembly/pseudocode xuất từ IDA guest |
| `analysis/static_summary.json`, `static-findings.md`, `lab13-02.md` | Metadata PE, raw dữ liệu và thuật toán; static-verification.json đối chiếu byte/hash |
| `analysis/lab13-03-crypto-audit.json`, `lab03-diagnostic.md` | CBC/key/IV tĩnh; không suy ra runtime thành công |
| `analysis/verification-matrix.json` | Từng claim: đã xác nhận/thiếu GUI/chưa xác nhận runtime |
| `analysis/runtime-verification.json`, `runtime-verification.md`, `verify_runtime.py` | Đo khoảng thời gian, đối chiếu CSV/JSON, test marker không thành công |
| `artifacts/Lab13-filtered.pml` | Phiên đầu:5.479sự kiện lọc, không phải log hệ thống đầy đủ |
| `artifacts/verification/verify-all.pml`, `verify-runtime.csv` | Phiên bổ sung:4.724sự kiện; PML lưu qua Procmon GUI |
| `artifacts/verification/*.json`, `*.jsonl` | PID/kết nối/HTTP body và fixed-marker observer |
| `artifacts/temp002a9d1e.enc`, `recovered.bmp`, `recovered.png` | Phiên đầu: ciphertext và ảnh giải mã1505×903 |
| `artifacts/verification/temp00ca77b9.enc`, `recovered-verify.bmp` | Phiên bổ sung: ciphertext và BMP1507×906 |
| `artifacts/decrypt_rabbit.py` | Decoder riêng biến thể mẫu02, có self-check |
| `analysis/verify_services.py` | Observer dùng trong guest: HTTP body o, TCP gửi một fixed marker; không chạy trên host |
| `analysis/final-isolation.json`, `vm-final-*.txt` | Kiểm tra cuối guest và cấu hình VMware |
| `analysis/cleanup-result.json`, `artifact-verification.json`, `controller-exit.json` | Kết quả lịch sử phiên đầu; không đại diện trạng thái cuối lượt bổ sung |
| `artifacts/spa_ui_preview.png` | Preview web, không phải evidence malware |
| `SHA256SUMS.txt` | SHA256 mọi tệp trong gói, trừ chính manifest |

## Giới hạn bắt buộc giữ
- NIC ngắt kết nối ngoài; hosts tạm trỏ domain về127.0.0.1. HTTP200 từ dịch vụ
  kiểm tra, không phải C2 Internet. Observer80/8910 bind127.0.0.1; Burp8080 bind:: theo preflight, không gọi mọi listener là loopback-only. Không có PCAP.
- Mẫu03 nhận28B trên socket; chưa chứng minh decoder malware, stdin pipe,
  thực thi echo hoặc AES outbound. Cipher capture0B; nguyên nhân chưa xác định.
- Key/IV/CBC được xác định tĩnh. Feedback liên tục, không reset IV mỗi message.
- BMP khôi phục hợp lệ, không có plaintext độc lập trước mã hóa để so byte-for-byte.
- Shared folder bật/ghi được trong lượt bổ sung; không air-gap.
- Thông tin OS dùng CIM10.0.19044, không dùng watermark desktop làm bằng chứng.
- Không có EXE/DLL mẫu malware trong gói. Mẫu gốc vẫn trong guest.

## Kết thúc môi trường
Không còn tiến trình Lab13 hoặc observer; hosts byte-exact/proxy ban đầu đã khôi phục,
controller đã dừng. Share gốc readonly được guest thử ghi và nhận Access denied.
Share tạm có present=false/enabled=false/writeAccess=false trong runtimeConfig/VMX;
guest còn thấy cache đường Lab13Transfer, không khẳng định đường này đã biến mất.
Ethernet0 Disconnected, startConnected=false. Giữ snapshot trước phân tích, không revert.

## Kiểm tra ngoại tuyến
Các lệnh chỉ đọc artifact, không chạy malware:

```powershell
python -B ".\artifacts\decrypt_rabbit.py" --test
python -B ".\analysis\verify_runtime.py"
python -B ".\qa_spa.py"
```

Decoder và runtime checker dùng stdlib. Runtime checker mặc định chỉ đọc; `--write-report` mới ghi lại JSON. QAweb cần Playwright/Edge đã cài;
mở SPA thông thường không cần. PASS kiểm tra artifact/UI không thay kiểm chứng live.
