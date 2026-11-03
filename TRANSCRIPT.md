# KỊCH BẢN THUYẾT MINH VIDEO LAB 13 (IAM302)
## Phân Tích Mã Độc Chapter 13: Data Encoding

> **Lưu ý:** Chỉ quay màn hình SPA. Lời đọc bám sát từng bước, ảnh minh chứng hiển thị ngay bên dưới.

---

## MỞ ĐẦU

- Tab `Bắt đầu` (`tab-overview`). Đưa phần đầu trang vào khung hình.

> "Kính chào Thầy/Cô. Em là **[Họ và tên sinh viên]**, MSSV **[MSSV]**. Theo yêu cầu môn học, em lấy 3 số cuối MSSV chia lấy dư cho 22 được số dư 13, thực hiện phân tích 3 mẫu trong thư mục **Chapter_13L** (Data Encoding) gồm `Lab13-01.exe`, `Lab13-02.exe` và `Lab13-03.exe`. Kết quả phân tích tĩnh và thực nghiệm được tích hợp trên trang SPA này, với ảnh chụp công cụ chuyên nghiệp đặt ngay dưới từng bước giải thích cơ chế. Sau đây em xin bắt đầu."

---

## PHẦN 1: TỔNG QUAN & XÁC ĐỊNH MẪU

### 1.1. Xác định đúng ba mẫu trước khi phân tích
- Tab `Bắt đầu` (`tab-overview`): Đưa mục vào khung hình; hiển thị ảnh EVID-23.

> "Em trình bày ba mẫu thuộc folder 13 của Practical Malware Analysis. Trước tiên là ảnh HashMyFiles để xác định đúng các tệp đang phân tích. Mã băm giúp đối chiếu mẫu, còn kết luận về hành vi sẽ dựa vào IDA và các công cụ giám sát ở những phần tiếp theo."

### 1.2. Phân biệt mã máy, hành vi đã chạy và kết quả khôi phục
- Tab `Bắt đầu` (`tab-overview`): Đưa mục vào khung hình; hiển thị ảnh EVID-05.

> "Bài này kết hợp phân tích tĩnh và phân tích động. IDA giải thích cơ chế trong mã máy; Burp và Procmon đối chiếu hành vi khi chạy. Ở đây là cấu hình bộ lọc Procmon, chưa phải kết quả phát hiện. Các ảnh tiếp theo được đặt ngay dưới nhận định tương ứng để người xem đối chiếu trực tiếp."

---

## PHẦN 2: LAB13-01.EXE

**[Chuyển tab]:** Sang `tab-sample-lab13-01` (Lab13-01.exe).

### 2.1. Địa chỉ máy chủ được giấu bằng XOR như thế nào?
- Tab `tab-sample-lab13-01`: Đưa mục vào khung hình; hiển thị ảnh EVID-02, EVID-03.

> "Lab13-01 là một beacon HTTP. Ảnh assembly cho thấy vòng lặp XOR với khóa 0x3B; ảnh mã giả ngay dưới thể hiện cùng phép biến đổi rõ hơn. Đối chiếu Resource 101 thu được domain www.practicalmalwareanalysis.com. Phép XOR này dành cho domain, không phải hostname của máy."

### 2.2. Hostname được đưa vào URL bằng Base64 chuẩn
- Tab `tab-sample-lab13-01`: Đưa mục vào khung hình; hiển thị ảnh EVID-29, EVID-30.

> "Tiếp theo, mẫu lấy hostname và chỉ giữ 12 byte đầu. Với máy lab, phần đó là DESKTOP-V5VC, được biểu diễn Base64 thành chuỗi REVTS1RPUC1WNVZD. Ảnh IDA cho thấy đoạn lấy hostname và một phần bảng ký tự. Kết luận bảng chuẩn đã được đối chiếu với dữ liệu đầy đủ, không chỉ dựa vào phần đang nhìn thấy."

### 2.3. Burp ghi nhận đúng request mà mã máy dự kiến
- Tab `tab-sample-lab13-01`: Đưa mục vào khung hình; hiển thị ảnh EVID-04, EVID-09.

> "Đến phần thực nghiệm, ảnh Burp ghi nhận GET với đúng đường dẫn Base64 vừa phân tích. Trường Host vẫn là domain trong mẫu, nhưng địa chỉ đích của bài lab là 127.0.0.1. Vì vậy đây là beacon được quan sát trong môi trường mô phỏng cục bộ, không phải kết nối ra máy chủ Internet."

### 2.4. Phản hồi o yêu cầu kết thúc, nhưng vẫn còn lần ngủ 30 giây
- Tab `tab-sample-lab13-01`: Đưa mục vào khung hình; hiển thị ảnh EVID-28, EVID-31, EVID-32.

> "Ở đây có một chi tiết dễ nhầm: nhận chữ o không làm chương trình thoát ngay. IDA cho thấy main luôn ngủ 30 giây sau beacon, rồi mới kiểm tra cờ. Ảnh tiếp theo là phép so sánh byte đầu với 111, tức chữ o. Burp xác nhận response thực tế có đúng một byte o."

### 2.5. Procmon xác nhận tiến trình tự kết thúc, không tự xóa tệp
- Tab `tab-sample-lab13-01`: Đưa mục vào khung hình; hiển thị ảnh EVID-37.

> "Cuối cùng, Procmon ghi nhận PID 4992 kết thúc với Exit Status bằng 0. Đối chiếu mốc nhận dữ liệu với mốc thoát cho khoảng 30,021 giây, phù hợp lần ngủ cuối trong mã máy. Phiên này không bị kill. Kết luận là tự kết thúc tiến trình, không gọi là tự xóa hay tự hủy."

---

## PHẦN 3: LAB13-02.EXE

**[Chuyển tab]:** Sang `tab-sample-lab13-02` (Lab13-02.exe).

### 3.1. Mẫu thứ hai thu thập ảnh desktop bằng GDI
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-10.

> "Lab13-02 có mục tiêu khác: chụp màn hình desktop. Ảnh IDA cho thấy các API GDI, đặc biệt là BitBlt, cùng cấu hình bitmap 32 bit mỗi pixel. Đây là căn cứ tĩnh cho chức năng chụp ảnh; những phần sau sẽ đối chiếu với tệp thật mà mẫu tạo ra."

### 3.2. Ảnh được che giấu bằng biến thể Rabbit với trạng thái ban đầu bằng 0
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-34, EVID-12.

> "Dữ liệu ảnh không được lưu rõ mà đi qua một biến thể Rabbit. Ảnh đầu cho thấy 68 byte trạng thái bị đặt về 0. Ảnh sau là các hằng số cập nhật counter, đang hiển thị ở hệ thập phân. Đối chiếu cấu trúc và hằng số cho thấy đây là biến thể, nên khi giải mã phải bám đúng triển khai trong mẫu."

### 3.3. Mẫu ghi tệp temp ngay tại thư mục làm việc
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-11, EVID-07, EVID-06, EVID-08.

> "Hàm điều phối chụp ảnh, mã hóa rồi tạo tên tệp từ GetTickCount. Trong Procmon, cửa sổ thuộc tính xác định thư mục làm việc là C:\Lab13Analysis\runtime. Dòng WriteFile bên dưới ghi nhận tệp temp002a9d1e với hơn 5,4 triệu byte. Vì vậy chữ temp ở đây là tên tệp, không phải bằng chứng mẫu ghi vào thư mục Temp của Windows."

### 3.4. Chu kỳ thực tế khoảng 10 giây, không phải 5 giây
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-33, EVID-38.

> "Chu kỳ là điểm cần đọc kỹ. Main có hai lần ngủ 5 giây chứ không phải một. Ảnh Procmon của lượt bổ sung ghi hai lần WriteFile cùng PID cách nhau khoảng 10,222 giây. Kích thước tệp ở lượt này lớn hơn lượt đầu do desktop khác kích thước, không phải hai kết quả mâu thuẫn."

### 3.5. HxD đối chiếu tệp mã hóa với cấu trúc BMP sau khôi phục
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-19, EVID-20.

> "Hai ảnh HxD sử dụng cùng tệp của lượt đầu. Trước giải mã, dữ liệu bắt đầu bằng E2 EE. Sau giải mã, đầu tệp trở thành BM và header mô tả bitmap 1505 nhân 903, 32 bit mỗi pixel. Đây là kiểm tra cấu trúc thực tế, không chỉ đổi tên hay đổi phần mở rộng."

### 3.6. Paint mở được ảnh desktop đã khôi phục
- Tab `tab-sample-lab13-02`: Đưa mục vào khung hình; hiển thị ảnh EVID-21.

> "Paint mở được tệp khôi phục và hiển thị desktop có cửa sổ Procmon. Kết quả này nối lại với hàm BitBlt ở đầu phần phân tích. Có thể kết luận mẫu chụp và lưu ảnh màn hình đã mã hóa; không mở rộng thành khẳng định đã gửi ảnh qua mạng. Mẫu được dừng sau khi quan sát."

---

## PHẦN 4: LAB13-03.EXE

**[Chuyển tab]:** Sang `tab-sample-lab13-03` (Lab13-03.exe).

### 4.1. Mẫu thứ ba có kiến trúc reverse shell TCP
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-13.

> "Lab13-03 có kiến trúc reverse shell. Mẫu chủ động kết nối về cổng 8910, dự kiến nhận lệnh và chuyển kết quả của cmd.exe về đầu điều khiển. Ảnh main cho thấy phần thiết lập này. Từ đầu cần phân biệt kiến trúc tìm thấy trong mã với phần đã chạy thành công trong thực nghiệm."

### 4.2. Anonymous pipe nối dữ liệu mạng với đầu vào, đầu ra cmd.exe
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-14, EVID-26, EVID-27.

> "Mẫu dùng hai cặp pipe để nối dữ liệu với cmd.exe. Ảnh đầu chỉ là khai báo biến. Ảnh tiếp theo mới cho thấy CreatePipe, còn ảnh cuối thể hiện gán các handle vào đầu vào, đầu ra, lỗi và gọi CreateProcessA. Ba ảnh có vai trò khác nhau, không dùng một ảnh khai báo để khẳng định toàn bộ luồng đã chạy."

### 4.3. Chiều nhận lệnh dùng Custom Base64
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-36, EVID-16.

> "Chiều nhận dùng Custom Base64, với bảng bắt đầu bằng chữ C. Ảnh bảng ký tự giải thích sự khác biệt; ảnh worker cho thấy đọc socket, giải dữ liệu rồi ghi vào pipe. Đây là luồng trong mã máy. Không vì nhìn thấy hàm decode mà khẳng định payload thử nghiệm đã được giải mã thành công."

### 4.4. Chiều gửi kết quả dùng AES-128-CBC, không phải Custom Base64
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-35, EVID-15.

> "Chiều gửi khác chiều nhận: đầu ra shell được mã hóa AES-128-CBC. Ảnh đầu cho thấy XOR với feedback, gọi lõi mã hóa rồi cập nhật feedback. Ảnh worker nối phần đó với stdout và socket. Khóa được đối chiếu là ijklmnopqrstuvwx, IV ban đầu bằng 0. Đây là AES cài trong mẫu, không phải CryptoAPI."

### 4.5. Procmon xác nhận mẫu đã tạo cmd.exe
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-18, EVID-22.

> "Về hành vi đã chạy, Procmon ghi nhận Lab13-03 tạo cmd.exe. Ảnh thuộc tính xác định tiến trình cha PID 4336 và tiến trình con PID 4532. Đây là bằng chứng động của việc tạo shell. Chưa thể từ quan hệ cha–con này suy ra lệnh từ mạng đã chạy."

### 4.6. Process Hacker xác nhận kết nối TCP tới cổng 8910
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị ảnh EVID-24, EVID-25.

> "Process Hacker ghi nhận kết nối TCP Established tới cổng 8910. Hai ảnh này thuộc lượt PID 5188, khác lượt Procmon vừa xem. Trạng thái Established chỉ xác nhận kết nối TCP. Nó không tự chứng minh lệnh đã được decode, đã chạy trong cmd.exe hay đã có dữ liệu AES gửi về."

### 4.7. Phần chưa chứng minh: lệnh kiểm tra và phản hồi AES runtime
- Tab `tab-sample-lab13-03`: Đưa mục vào khung hình; hiển thị bảng số liệu kiểm chứng runtime.

> "Lượt bổ sung nhận được 28 byte payload thử nghiệm, nhưng phía thu không có byte phản hồi nào. Vì vậy em chưa kết luận lệnh echo đã chạy hay đường AES outbound đã hoàn tất. Nguyên nhân chưa được xác định. Kết quả mẫu ba là xác nhận được kiến trúc và một phần hành vi, không phải kiểm chứng end-to-end thành công."

---

## KẾT LUẬN & GIỚI HẠN

**[Chuyển tab]:** Sang `tab-iocs` (Kết luận & IOC).

- Tab `Kết luận & IOC` (`tab-iocs`): Đưa bảng IOC và kết luận vào khung hình.

> "Kính thưa Thầy/Cô, tổng kết 3 mẫu Chapter 13:
>
> - **Lab13-01:** beacon HTTP, URL XOR 0x3B, hostname Base64 chuẩn; nhận o tự thoát sau 30 giây ngủ, hiện chưa có bằng chứng tự xóa tệp.
> - **Lab13-02:** chụp màn hình GDI, mã hóa biến thể Rabbit zero-state, ghi tệp temp%08x tại CWD khoảng mỗi 10 giây (thực nghiệm 10.222 giây); ảnh sau giải mã hiển thị đúng desktop.
> - **Lab13-03:** reverse shell cổng 8910, nhận lệnh qua Custom Base64, mã máy cho thấy gửi dữ liệu bằng AES-128-CBC (không khẳng định gửi thành công ở runtime); thực nghiệm ghi nhận tạo cmd.exe và nhận 28 byte trên socket, chưa thu được phản hồi outbound.
>
> Về môi trường: Mạng ngoài ngắt, dịch vụ mô phỏng nội bộ; do có shared folder nên không phải air-gap hoàn toàn. Báo cáo phân định rõ giữa thiết kế tĩnh và kết quả thực nghiệm.
>
> Em xin cảm ơn Thầy/Cô."
