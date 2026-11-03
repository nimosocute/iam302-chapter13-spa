window.LAB13 = {
  "meta": {
    "title": "Chapter 13 — Phân tích Malware & Bằng chứng",
    "subtitle": "Folder 13 · 3 mẫu · 36 ảnh toàn màn hình VMware · Tĩnh / runtime phân biệt",
    "folderNumber": 13,
    "folderPath": "C:\\Users\\bachdeptrai\\Downloads\\PracticalMalwareAnalysis-Labs-master\\PracticalMalwareAnalysis-Labs\\Practical Malware Analysis Labs\\BinaryCollection\\Chapter_13L",
    "environment": {
      "os": "Microsoft Windows 10 Enterprise LTSC Evaluation, Version 10.0.19044 Build 19044 (64-bit; CIM)",
      "vm": "VMware Workstation 17.6.2 build-24409262 (Host: Windows 11)",
      "network": "Ethernet0 Disconnected; startConnected=false. Observer80/8910 bind127.0.0.1; Burp8080 bind:: theo preflight. Share bật/ghi được trong lượt bổ sung; cuối phiên share gốc readonly, guest thử ghi bị từ chối. Không air-gap.",
      "snapshot": "Lab13-before-analysis-20261102",
      "tools": [
        "IDA Pro 9.4 (Interactive Disassembler)",
        "Process Monitor (Procmon v3.96) - Sysinternals",
        "Burp Suite Professional v2023.4.2",
        "Process Hacker",
        "HxD Hex Editor",
        "HashMyFiles (NirSoft)",
        "Microsoft Paint"
      ]
    }
  },
  "samples": [
    {
      "id": "lab13-01",
      "fileName": "Lab13-01.exe",
      "arch": "PE32 x86 (Native 32-bit)",
      "fileSize": 32768,
      "md5": "a9a2734d080e3ae0f5ada35e878da7c8",
      "sha256": "71a295247ba7419f9f9dea8098e6867182bb80f53c98eb0f59192a6557a51249",
      "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI (3) - Windows Console",
      "status": "Tĩnh + HTTP Loopback + Tự thoát đã quan sát",
      "overview": "Mã độc do thám hostname máy nạn nhân, mã hóa chuỗi bằng Base64 chuẩn và gửi HTTP GET beacon tới C2 server được giải mã từ Resource.",
      "mechanism": {
        "algorithm": "Single-byte XOR (Key 0x3B) + Standard Base64",
        "keyOrTable": "XOR Key: 0x3B (0x4C ^ 0x3B = \"w\")\nBase64 Table (VA 0x004050e8):\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "description": "1. Resource 101 (RT_RCDATA, 32 byte, VA 0x00408060) được sub_401190 XOR 0x3B, thu được www.practicalmalwareanalysis.com.\n2. sub_4011C9 lấy hostname, sao chép 12 byte đầu và thêm null terminator; sub_4010B1 dùng Base64 chuẩn, alphabet tại 0x004050E8.\n3. Gửi GET http://www.practicalmalwareanalysis.com/<base64_hostname>/ qua WinINet. DESKTOP-V5VC9B3 được rút thành DESKTOP-V5VC, tương ứng REVTS1RPUC1WNVZD.\n4. main 0x004013ED: Sleep(500), gọi beacon, luôn Sleep(30000), rồi mới xét cờ trả về. Hàm beacon trả về Buffer[0] == 111, tức ký tự 'o'. Nếu đúng, main gọi WSACleanup và return 0; không có xóa file/tự hủy.\n5. Lượt quan sát đầu trả body khác 'o': hai GET cách nhau 30.606385 giây. Lượt bổ sung trả body 'o' thật qua Burp: PID 4992 tự thoát Exit Status 0, không bị kill; TCP Receive đến Process Exit cách 30.0210184 giây.",
        "disassemblySnippet": "; IDA export: sub_401190\n0x004011a6: mov     ecx, [ebp+var_4]\n0x004011a9: cmp     ecx, [ebp+arg_4]\n0x004011ac: jnb     short loc_4011C5\n0x004011ae: mov     edx, [ebp+arg_0]\n0x004011b1: add     edx, [ebp+var_4]\n0x004011b4: xor     eax, eax\n0x004011b6: mov     al, [edx]\n0x004011b8: xor     eax, 3Bh\n0x004011bb: mov     ecx, [ebp+arg_0]\n0x004011be: add     ecx, [ebp+var_4]\n0x004011c1: mov     [ecx], al\n0x004011c3: jmp     short loc_40119D\n0x004011c5: mov     esp, ebp\n0x004011c7: pop     ebp\n0x004011c8: retn\n\n; IDA export: _main\n0x004013ed: push    ebp\n0x004013ee: mov     ebp, esp\n0x004013f0: sub     esp, 1A0h\n0x004013f6: mov     [ebp+var_4], 0\n0x004013fd: call    sub_401300\n0x00401402: mov     [ebp+var_19C], eax\n0x00401408: mov     [ebp+wVersionRequested], 202h\n0x00401411: lea     eax, [ebp+WSAData]\n0x00401417: push    eax; lpWSAData\n0x00401418: mov     cx, [ebp+wVersionRequested]\n0x0040141f: push    ecx; wVersionRequested\n0x00401420: call    WSAStartup\n0x00401425: mov     [ebp+var_4], eax\n0x00401428: cmp     [ebp+var_4], 0\n0x0040142c: jnz     short loc_40145E\n0x0040142e: push    1F4h; dwMilliseconds\n0x00401433: call    ds:Sleep; KERNEL32\n0x00401439: mov     edx, [ebp+var_19C]\n0x0040143f: push    edx\n0x00401440: call    sub_4011C9\n0x00401445: add     esp, 4\n0x00401448: mov     [ebp+var_8], al\n0x0040144b: push    7530h; dwMilliseconds\n0x00401450: call    ds:Sleep; KERNEL32\n0x00401456: movsx   eax, [ebp+var_8]\n0x0040145a: test    eax, eax\n0x0040145c: jz      short loc_40142E\n0x0040145e: call    WSACleanup\n0x00401463: xor     eax, eax\n0x00401465: mov     esp, ebp\n0x00401467: pop     ebp\n0x00401468: retn",
        "snippetLabel": "Trích đoạn assembly thật từ IDA (chưa đổi tên hàm)"
      },
      "findings": [
        {
          "title": "Trích xuất Resource ID 101 và giải mã C2 Domain",
          "status": "Verified (Static)",
          "detail": "Resource 101 dạng thô chứa 32 bytes bắt đầu bằng 4c 4c 4c 15. Áp dụng phép XOR với 0x3b thu được chuỗi C2: www.practicalmalwareanalysis.com."
        },
        {
          "title": "Quan sát thực nghiệm HTTP Beaconing trên Loopback",
          "status": "Verified (Observed)",
          "detail": "Trên testbed giả lập cục bộ, Lab13-01 phát sinh 2 yêu cầu GET /REVTS1RPUC1WNVZD/ tới Host www.practicalmalwareanalysis.com, User-Agent Mozilla/4.0 vào lúc unix 1793616907.618909 và 1793616938.225294 (khoảng cách 30.606 giây). Chuỗi REVTS1RPUC1WNVZD chính là Base64 của DESKTOP-V5VC (12 byte đầu của hostname máy ảo DESKTOP-V5VC9B3)."
        },
        {
          "title": "Phản hồi 'o' và lần ngủ 30 giây cuối đã được đối chiếu",
          "status": "Verified (Static + Observed)",
          "detail": "Ảnh 28/31: Sleep(30000) trước kiểm tra cờ; Buffer[0] == 111. Ảnh 32: HTTP 200, Content-Length 1, body o. Ảnh 37: PID 4992 Process Exit 20:37:29.0234778, Exit Status 0. CSV và lab01-exit.json xác nhận không forced kill; khoảng từ TCP Receive là 30.0210184s. Không gọi hành vi này là tự hủy: chưa thấy xóa mẫu."
        }
      ],
      "role": "Beacon HTTP, thu thập hostname"
    },
    {
      "id": "lab13-02",
      "fileName": "Lab13-02.exe",
      "arch": "PE32 x86 (Native 32-bit)",
      "fileSize": 32768,
      "md5": "b65c4d7cbc4069ddbff665370201e588",
      "sha256": "598f21f1e6f4d5829ba8cfba19d361e09de510493df8472a605f46dbf7927030",
      "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI (3) - Windows Console",
      "status": "Tĩnh + Quan sát thực nghiệm + Giải mã thành công",
      "overview": "Phần mềm gián điệp chụp ảnh màn hình desktop máy nạn nhân bằng GDI, mã hóa dữ liệu ảnh bằng biến thể Rabbit Stream Cipher và lưu ra tệp temp trong thư mục làm việc hiện tại.",
      "mechanism": {
        "algorithm": "Rabbit Stream Cipher (Biến thể hằng số 0x4D34D35D, Zero-State 68B)",
        "keyOrTable": "Rabbit-derived counter constants; offsets dưới đây là vị trí disp32 của lệnh LEA trong file:\n0x4D34D35D: 0x131e, 0x137e, 0x13de (RFC 4503 dùng 0x4D34D34D)\n0xD34D34D3: 0x133e, 0x139e, 0x13fe\n0x34D34D34: 0x135e, 0x13be\nState: 68 bytes (0x44) memset 0; không key schedule / warmup.",
        "description": "1. sub_401070 dùng GetDesktopWindow/GetDC, CreateCompatibleDC/CreateCompatibleBitmap, BitBlt SRCCOPY và GetDIBits tạo BMP desktop.\n2. sub_40181F memset state 68 byte về zero, gọi sub_401739 XOR keystream 16-byte từ biến thể Rabbit (counter 0x4D34D35D thay 0x4D34D34D chuẩn). Không key schedule/warmup trên đường gọi này.\n3. sub_401851 dùng GetTickCount tạo tên temp%08x trong thư mục làm việc hiện tại, không mặc định Windows Temp. WriteFile ghi đúng độ dài BMP, không thêm padding file ở khối cuối.\n4. main 0x004018D8: Sleep(5000); sub_401851(); Sleep(5000); lặp lại. Hai lần chụp cách nhau ít nhất 10 giây cộng thời gian xử lý, không phải 5 giây.\n5. Lượt đầu: 5.436.114 byte, BMP 1505×903. Lượt bổ sung PID 3876: hai WriteFile 5.461.422 byte cách 10.2218796s; temp00ca77b9 giải mã thành BMP 1507×906, 32 bpp. Kích thước phụ thuộc desktop từng lượt. Mẫu 02 được dừng cưỡng bức sau cửa sổ quan sát.",
        "disassemblySnippet": "; IDA export: sub_40181F\n0x0040181f: push    ebp\n0x00401820: mov     ebp, esp\n0x00401822: sub     esp, 44h\n0x00401825: push    44h ; 'D'; Size\n0x00401827: push    0; Val\n0x00401829: lea     eax, [ebp+var_44]\n0x0040182c: push    eax; void *\n0x0040182d: call    _memset\n0x00401832: add     esp, 0Ch\n0x00401835: mov     ecx, [ebp+arg_4]\n0x00401838: push    ecx\n0x00401839: mov     edx, [ebp+arg_0]\n0x0040183c: push    edx\n0x0040183d: mov     eax, [ebp+arg_0]\n0x00401840: push    eax\n0x00401841: lea     ecx, [ebp+var_44]\n0x00401844: push    ecx\n0x00401845: call    sub_401739\n0x0040184a: add     esp, 10h\n0x0040184d: mov     esp, ebp\n0x0040184f: pop     ebp\n0x00401850: retn\n\n; IDA export: sub_401851\n0x00401851: push    ebp\n0x00401852: mov     ebp, esp\n0x00401854: sub     esp, 20Ch\n0x0040185a: mov     [ebp+hMem], 0\n0x00401861: mov     [ebp+nNumberOfBytesToWrite], 0\n0x00401868: lea     eax, [ebp+nNumberOfBytesToWrite]\n0x0040186b: push    eax\n0x0040186c: lea     ecx, [ebp+hMem]\n0x0040186f: push    ecx\n0x00401870: call    sub_401070\n0x00401875: add     esp, 8\n0x00401878: mov     edx, [ebp+nNumberOfBytesToWrite]\n0x0040187b: push    edx\n0x0040187c: mov     eax, [ebp+hMem]\n0x0040187f: push    eax\n0x00401880: call    sub_40181F\n0x00401885: add     esp, 8\n0x00401888: call    ds:GetTickCount; KERNEL32\n0x0040188e: mov     [ebp+var_4], eax\n0x00401891: mov     ecx, [ebp+var_4]\n0x00401894: push    ecx\n0x00401895: push    offset Format; \"temp%08x\"\n0x0040189a: lea     edx, [ebp+Buffer]\n0x004018a0: push    edx; Buffer\n0x004018a1: call    _sprintf\n0x004018a6: add     esp, 0Ch\n0x004018a9: lea     eax, [ebp+Buffer]\n0x004018af: push    eax; lpFileName\n0x004018b0: mov     ecx, [ebp+nNumberOfBytesToWrite]\n0x004018b3: push    ecx; nNumberOfBytesToWrite\n0x004018b4: mov     edx, [ebp+hMem]\n0x004018b7: push    edx; lpBuffer\n0x004018b8: call    sub_401000\n0x004018bd: add     esp, 0Ch\n0x004018c0: mov     eax, [ebp+hMem]\n0x004018c3: push    eax; hMem\n0x004018c4: call    ds:GlobalUnlock; KERNEL32\n0x004018ca: mov     ecx, [ebp+hMem]\n0x004018cd: push    ecx; hMem\n0x004018ce: call    ds:GlobalFree; KERNEL32\n0x004018d4: mov     esp, ebp\n0x004018d6: pop     ebp\n0x004018d7: retn",
        "snippetLabel": "Trích đoạn assembly thật từ IDA (chưa đổi tên hàm)"
      },
      "findings": [
        {
          "title": "Cơ chế gián điệp màn hình GDI Screen Capture",
          "status": "Verified (Static)",
          "detail": "Mã độc sử dụng tập API GDI32 hoàn chỉnh (GetDesktopWindow, CreateCompatibleBitmap, BitBlt, GetDIBits) để kết xuất dữ liệu ảnh bitmap (.bmp) của toàn bộ không gian làm việc nạn nhân."
        },
        {
          "title": "Thuật toán Rabbit Stream Cipher với Zero 68-Byte State",
          "status": "Verified (Static)",
          "detail": "Phát hiện sự kết hợp của 3 hằng số đặc trưng của Rabbit cipher: 0x4D34D35D (biến thể so với RFC 4503), 0xD34D34D3 và 0x34D34D34. Bảng trạng thái nội bộ 68 bytes ban đầu được memset 0; không có key schedule hoặc warmup. Quá trình mã hóa duyệt khối 16 bytes và XOR keystream toàn diện."
        },
        {
          "title": "Quan sát thực nghiệm ghi tệp và giải mã thành công ảnh Bitmap",
          "status": "Verified (Observed + Decrypted)",
          "detail": "Trong quá trình chạy thực nghiệm, Lab13-02 đã gọi WriteFile tạo ra tệp temp002a9d1e trong thư mục làm việc hiện tại với dung lượng đúng 5,436,114 bytes. Thực hiện giải mã tệp này bằng thuật toán Rabbit stream đối xứng tương ứng đã thu được tệp ảnh Bitmap (.bmp) hợp lệ kích thước 1505 x 903 pixels, mang chữ ký magic header 'BM' (0x42 0x4D) chuẩn xác."
        },
        {
          "title": "Hai Sleep(5000), đối chiếu hai WriteFile cùng PID",
          "status": "Verified (Static + Observed)",
          "detail": "Ảnh 33 hiển thị cả hai Sleep(0x1388); ảnh 38 ghi PID 3876 WriteFile lúc 20:39:31.7045111 và 20:39:41.9263907, mỗi lần 5.461.422 byte. Khoảng đo 10.2218796s phù hợp vòng lặp. recovered-verify.bmp có header BM, 1507×906, 32 bpp; không có plaintext độc lập trước mã hóa để so sánh byte-for-byte."
        }
      ],
      "role": "Gián điệp chụp màn hình, mã hóa tệp cục bộ"
    },
    {
      "id": "lab13-03",
      "fileName": "Lab13-03.exe",
      "arch": "PE32 x86 (Native 32-bit)",
      "fileSize": 77824,
      "md5": "98ea0fe0594f0f373d9791886a01db8c",
      "sha256": "86054002565c929215b82615477652d24379b9119bc33ef7f41706ee7e125379",
      "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI (3) - Windows Console",
      "status": "Tĩnh + TCP/cmd.exe đã quan sát; echo chưa xác nhận",
      "overview": "Mã máy cho thấy reverse shell TCP 8910, pipe tới cmd.exe; inbound Custom Base64, outbound AES-128-CBC. Runtime xác nhận kết nối, tạo cmd.exe và nhận 28 byte; chưa xác nhận lệnh thực thi hay AES outbound.",
      "mechanism": {
        "algorithm": "Inbound: Custom Base64 (Shift-2) | Outbound: AES-128-CBC",
        "keyOrTable": "Custom Base64 Alphabet (VA 0x004120a4, Offset 0x120a4):\nCDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/\n\nAES-128 Key (VA 0x00412208): ijklmnopqrstuvwx\nAES S-Box chuẩn tại VA 0x0040c908 (63 7c 77 7b f2 6b 6f c5...)\nAES IV: 16 null bytes tại VA 0x00413374 (BSS zero-initialized)\nCBC feedback: context + 0x3F4; duy trì giữa các lần gọi, không reset IV cho từng message.\nĐối chiếu: 0x401BA9 nạp IV, 0x4035DB XOR, 0x4035F1 AES core, 0x40360D cập nhật feedback.",
        "description": "KẾT LUẬN TĨNH:\n1. main 0x00401879 khởi tạo Winsock, WSASocketA, kết nối www.practicalmalwareanalysis.com:8910.\n2. sub_4015B7 tạo hai anonymous pipe, thiết lập STARTF_USESTDHANDLES, kế thừa handle và CreateProcessA cmd.exe.\n3. Luồng inbound 0x0040147C đọc socket bằng ReadFile, giải mã Custom Base64 (sub_401082), WriteFile vào pipe stdin. Luồng outbound 0x0040132B đọc pipe stdout, làm tròn độ dài lên bội 16, gọi AES-128-CBC (sub_40352D), WriteFile ra socket. Hai hướng, không hai lớp lồng nhau.\n4. Key ijklmnopqrstuvwx; IV ban đầu zero, feedback context+0x3F4 được duy trì giữa các lượt gọi. Ảnh 35 hiển thị cấu trúc CBC, ảnh 36 alphabet.\nGIỚI HẠN RUNTIME:\n5. PID 5672 kết nối loopback 8910, sinh cmd.exe PID 1296, nhận 28 byte fixed test payload. Đối chiếu offline payload tương ứng echo LAB13_VERIFIED\\r\\n (21 byte). Observer nhận 0 byte outbound. Không có API trace chứng minh giải mã/ghi pipe/thực thi lệnh hoặc AES đã xảy ra. Nguyên nhân thiếu đầu ra chưa xác định; không coi buffering là sự thật đã xác nhận.",
        "disassemblySnippet": "; sub_4015B7: STARTF_USESTDHANDLES, CreateProcessA\n0x00401754  mov eax, [ebp-80h]\n0x00401757  or ah, 1                    ; bật cờ 0x100\n0x0040175A  mov [ebp-80h], eax\n...\n0x0040176E  push 1                      ; bInheritHandles\n0x00401774  push 004121BCh              ; \"cmd.exe\"\n0x00401779  push 0                      ; lpApplicationName\n0x0040177B  call dword ptr [0040C02Ch]  ; CreateProcessA\n\n; CreateThread inbound, tham số đẩy theo thứ tự phải-sang-trái\n0x004017F1  lea ecx, [ebp-0B0h]\n0x004017F7  push ecx                    ; lpThreadId\n0x004017F8  push 0                      ; dwCreationFlags\n0x004017FA  lea edx, [ebp-68h]\n0x004017FD  push edx                    ; lpParameter\n0x004017FE  push 0040147Ch              ; lpStartAddress\n0x00401803  push 0                      ; dwStackSize\n0x00401805  push 0                      ; lpThreadAttributes\n0x00401807  call dword ptr [0040C028h]  ; CreateThread\n\n; CreateThread outbound\n0x00401838  lea eax, [ebp-3Ch]\n0x0040183B  push eax                    ; lpThreadId\n0x0040183C  push 0                      ; dwCreationFlags\n0x0040183E  lea ecx, [ebp-58h]\n0x00401841  push ecx                    ; lpParameter\n0x00401842  push 0040132Bh              ; lpStartAddress\n0x00401847  push 0                      ; dwStackSize\n0x00401849  push 0                      ; lpThreadAttributes\n0x0040184B  call dword ptr [0040C028h]  ; CreateThread",
        "snippetLabel": "Assembly đối chiếu trực tiếp từ binary; chú thích tham số"
      },
      "findings": [
        {
          "title": "Cấu trúc Reverse Shell đa luồng và chuyển hướng Anonymous Pipes",
          "status": "Pipes: phân tích tĩnh; tạo cmd.exe: đã quan sát",
          "detail": "Mã độc khởi tạo cmd.exe với thuộc tính kế thừa handles, chuyển hướng toàn bộ luồng nhập xuất chuẩn thông qua cặp đường ống ẩn danh do CreatePipe tạo lập."
        },
        {
          "title": "Tách bạch giải mã Inbound vs Outbound",
          "status": "Verified (Static)",
          "detail": "Phân tích mã máy chứng minh rõ ràng: Luồng nhận lệnh Inbound (0x0040147c) chỉ xử lý giải mã Custom Base64 (bảng xoay trái 2 vị trí bắt đầu bằng chữ C). Ngược lại, luồng Outbound (0x0040132b) chỉ thực hiện mã hóa AES-128-CBC với khóa cố định \"ijklmnopqrstuvwx\". Không có lớp mã hóa lồng nhau."
        },
        {
          "title": "Quan sát tiến trình và kết nối Socket trong môi trường sống",
          "status": "Verified (Observed)",
          "detail": "Lần chạy PID 4336 sinh cmd.exe PID 4532 và conhost.exe PID 712; snapshot TCP ghi 127.0.0.1:49747 kết nối 127.0.0.1:8910 (Established). Observer thụ động nhận 0 byte, không gửi lệnh. Ảnh 24–25 thuộc lần chạy sau, PID 5188, local port 49774; không coi đó là cùng snapshot JSON. Lượt bổ sung: PID 5672, cmd.exe PID 1296, local port 49777; Procmon TCP Receive 28 byte lúc 20:40:43.4519532. Listener gửi BYPqdaDOSWKzO19YTXLLTmnHTC0M; đối chiếu offline là echo LAB13_VERIFIED\\r\\n, không phải shellcode. Cipher capture vẫn 0 byte; test echo chưa thành công, nguyên nhân chưa xác định."
        },
        {
          "title": "Chưa chứng minh end-to-end echo / AES runtime",
          "status": "Unproven (Runtime)",
          "detail": "Có TCP Receive không đồng nghĩa cmd.exe đã nhận lệnh qua pipe. Không có stdout/ciphertext thu được để giải mã kiểm tra marker. Không suy ra hàm AES chưa chạy hoặc đang kẹt ReadFile khi thiếu trace."
        }
      ],
      "role": "Reverse shell TCP, chuyển hướng cmd.exe"
    }
  ],
  "iocs": [
    {
      "type": "Domain / Hostname",
      "sample": "Lab13-01.exe",
      "indicator": "www.practicalmalwareanalysis.com",
      "context": "C2 Domain được giấu trong Resource 101, giải mã bằng XOR 0x3B",
      "severity": "High"
    },
    {
      "type": "URL Path Template",
      "sample": "Lab13-01.exe",
      "indicator": "http://www.practicalmalwareanalysis.com/<base64_hostname>/",
      "context": "Mẫu định dạng URL beacon qua WinINet (User-Agent: Mozilla/4.0)",
      "severity": "High"
    },
    {
      "type": "File Artifact Pattern",
      "sample": "Lab13-02.exe",
      "indicator": "temp%08x",
      "context": "Tệp dữ liệu ảnh chụp màn hình mã hóa Rabbit Stream Cipher, sinh từ GetTickCount trong thư mục làm việc hiện tại",
      "severity": "Medium"
    },
    {
      "type": "Domain / TCP Port",
      "sample": "Lab13-03.exe",
      "indicator": "www.practicalmalwareanalysis.com:8910",
      "context": "Đích TCP outbound của mẫu; malware không mở cổng listen 8910",
      "severity": "High"
    },
    {
      "type": "Crypto Key (AES-128)",
      "sample": "Lab13-03.exe",
      "indicator": "ijklmnopqrstuvwx",
      "context": "Khóa đối xứng 16 bytes dùng để mã hóa luồng dữ liệu trả về C2",
      "severity": "High"
    },
    {
      "type": "Custom Base64 Alphabet",
      "sample": "Lab13-03.exe",
      "indicator": "CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/",
      "context": "Bảng ký tự Base64 biến thể dùng để giải mã lệnh nhận từ C2",
      "severity": "Medium"
    }
  ],
  "reproduction": [
    {
      "step": 1,
      "title": "Chuẩn bị và nhận diện mẫu",
      "action": "Tạo snapshot Lab13-before-analysis-20261102; ngắt Ethernet0. HashMyFiles xác nhận đúng 3 mẫu Chapter_13L. Giữ mẫu gốc, dùng bản sao C:\\Lab13Analysis\\samples.",
      "expectation": "Đối chiếu SHA256 và phạm vi folder 13; không kết nối C2 ngoài Internet."
    },
    {
      "step": 2,
      "title": "Đọc cơ chế trong IDA Pro",
      "action": "Theo các VA trong từng tab: XOR 0x401190; GDI 0x401070 và Rabbit 0x4012DD; main 0x401879, pipes 0x4015B7, inbound 0x40147C và outbound 0x40132B.",
      "expectation": "Đối chiếu cơ chế và VA với ảnh 02–04, 10–16, 26–36; ảnh 30 chỉ có một phần alphabet, bảng đủ 64 ký tự nằm trong static_summary.json."
    },
    {
      "step": 3,
      "title": "Thiết lập quan sát cục bộ",
      "action": "Burp chỉ mở từ C:\\Users\\bachdeptrai\\Desktop\\Burp Suite Pro.lnk. Proxy 127.0.0.1:8080, hosts trỏ domain về loopback. Phiên đầu HTTP trả lab13-local-observation, TCP observer chỉ nhận. Phiên kiểm chứng bổ sung HTTP trả đúng o; TCP gửi duy nhất fixed marker, đóng sau cửa sổ giới hạn.",
      "expectation": "Mô phỏng dịch vụ kiểm tra có ghi rõ nguồn phản hồi, không coi HTTP 200 là C2 thật."
    },
    {
      "step": 4,
      "title": "Chạy giới hạn thời gian, chụp GUI",
      "action": "Mẫu chỉ chạy trong guest, từ bản sao C:\\Lab13Analysis\\samples. Chụp GUI công cụ thật, nguyên màn hình host có VMware; không crop/ghép. Lượt bổ sung có shared folder bật/ghi được, không tuyên bố air-gap. Sau yêu cầu chạy ẩn: không điều khiển màn hình/chuột, chỉ đối chiếu artifact.",
      "expectation": "36 PNG gốc; nhãn tĩnh/runtime và giới hạn quan sát riêng từng ảnh."
    },
    {
      "step": 5,
      "title": "Kiểm chứng artifact, lưu log",
      "action": "Lưu PML bằng Procmon GUI. Giữ hai phiên riêng: Lab13-filtered.pml (5.479 sự kiện) và verification/verify-all.pml (4.724 sự kiện). CSV/JSON và decoder dùng kiểm tra ngoại tuyến, không thay ảnh GUI.",
      "expectation": "Lượt đầu BMP 1505×903 / 5.436.114 byte; lượt bổ sung 1507×906 / 5.461.422 byte. Đối chiếu runtime 01:30.0210184s, 02:10.2218796s, 03:28 byte inbound / 0 byte outbound."
    },
    {
      "step": 6,
      "title": "Kết thúc phiên",
      "action": "Dừng mẫu/observer; khôi phục hosts byte-exact và proxy; controller đã dừng. Share gốc readonly, guest thử ghi bị Access denied. Cấu hình share tạm disabled/present=false; guest vẫn thấy đường Lab13Transfer trong cache, không tuyên bố đường dẫn đã biến mất. Ethernet0 Disconnected, startConnected=false; không revert snapshot.",
      "expectation": "final-isolation.json và vm-final-*.txt ghi trạng thái cuối, tách kiểm tra guest thực tế khỏi runtimeConfig/VMX."
    }
  ],
  "limitations": [
    "Kết nối mạng ngoài bị ngắt; domain được trỏ tạm về 127.0.0.1. Response HTTP 200 do observer cục bộ tạo, không chứng minh liên lạc C2 Internet.",
    "Không có PCAP do thiếu driver capture phù hợp. Burp chỉ chứng minh HTTP qua proxy; log Procmon được xuất theo bộ lọc, không phải toàn bộ hoạt động hệ thống.",
    "Lab13-03 nhận 28 byte fixed marker, nhưng observer nhận 0 byte outbound. Chưa xác nhận malware giải mã, ghi stdin, cmd.exe thực thi hay AES runtime. Nguyên nhân thiếu đầu ra chưa xác định.",
    "AES-128-CBC và Custom Base64 của Lab13-03 được xác định từ mã máy và luồng dữ liệu; không dùng socket Established làm bằng chứng crypto runtime.",
    "Lab13-02 giải mã được BMP có header, chiều dài và ảnh hiển thị hợp lệ. Không có plaintext độc lập trước mã hóa để chứng minh khôi phục byte-for-byte.",
    "Ảnh GUI được chụp thật, không crop hoặc ghép. Có hỗ trợ tự động điều khiển và trích xuất; ảnh không tự chứng minh thao tác thủ công hay danh tính sinh viên.",
    "Chưa cung cấp tên/MSSV; chỉ dùng folder 13 đã xác nhận. Các công cụ hiển thị sự kiện/chức năng, không có nghĩa tất cả đều tự kết luận mẫu là malware.",
    "Chưa có ảnh GUI raw Resource 101 hoặc Burp Decoder hostname; ảnh 30 chỉ hiển thị một phần alphabet. Raw export/kiểm tra offline hỗ trợ các kết luận tương ứng, không được gọi là đã chụp đủ mọi bước.",
    "Shared folder bật và ghi được trong lượt kiểm chứng bổ sung. Cuối phiên share gốc đã readonly qua guest probe; cấu hình share tạm đã tắt nhưng guest vẫn thấy cache đường Lab13Transfer. Không khẳng định air-gap.",
    "Preflight ghi Burp8080 bind:: (wildcard IPv6), còn observer80/8910 bind127.0.0.1; NIC ngắt. Không tuyên bố mọi listener chỉ bindloopback."
  ],
  "references": [
    {
      "title": "Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software",
      "author": "Michael Sikorski & Andrew Honig",
      "chapter": "Chapter 13: Data Encoding",
      "note": "Sách giáo trình nền tảng phân tích kỹ thuật nhận diện các giải thuật XOR, Base64, Rabbit Cipher và Reverse Shell redirection.",
      "url": "https://nostarch.com/malware"
    },
    {
      "title": "RFC 4503: A Description of the Rabbit Stream Cipher",
      "author": "M. Boesgaard et al.",
      "chapter": "Cryptography Standard",
      "note": "Đặc tả kỹ thuật của Rabbit Stream Cipher với các hằng số trạng thái g, a, b (lưu ý biến thể 0x4D34D35D trong mẫu Lab13-02).",
      "url": "https://datatracker.ietf.org/doc/html/rfc4503"
    },
    {
      "title": "NIST FIPS 197: Advanced Encryption Standard (AES)",
      "author": "National Institute of Standards and Technology",
      "chapter": "Rijndael Specification",
      "note": "Đặc tả AES và S-box; chế độ CBC được đối chiếu riêng với SP 800-38A.",
      "url": "https://csrc.nist.gov/publications/detail/fips/197/final"
    },
    {
      "title": "NIST SP 800-38A — Block Cipher Modes of Operation",
      "author": "NIST",
      "chapter": "CBC",
      "note": "Đặc tả CBC; phân biệt nhận diện thuật toán và quan sát ciphertext thực tế.",
      "url": "https://csrc.nist.gov/pubs/sp/800/38/a/final"
    },
    {
      "title": "RFC 4648 — Base16, Base32, and Base64 Data Encodings",
      "author": "S. Josefsson",
      "chapter": "Base64",
      "note": "Alphabet Base64 chuẩn dùng đối chiếu với bảng biến thể của mẫu 03.",
      "url": "https://www.rfc-editor.org/rfc/rfc4648"
    }
  ],
  "evidences": [
    {
      "id": "EVID-02",
      "sampleId": "lab13-01",
      "tool": "IDA Pro 9.4",
      "imagePath": "evidence/02-ida-lab01-xor3b.png",
      "title": "Vòng lặp giải mã XOR 0x3B trong IDA Pro (sub_401190)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Đồ họa hợp ngữ (Disassembly Graph) của hàm sub_401190 trong Lab13-01.exe. Vòng lặp duyệt mảng byte từ Resource 101, thực hiện lệnh xor eax, 3Bh và lưu lại qua mov [ecx], al để giải mã địa chỉ C2 URL.",
      "observation": "Vòng lặp duyệt mảng byte từ Resource 101, thực hiện lệnh xor eax, 3Bh và lưu lại qua mov [ecx], al để giải mã địa chỉ C2 URL.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-03",
      "sampleId": "lab13-01",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/03-ida-lab01-decompiler-xor.png",
      "title": "Mã giả Hex-Rays thuật toán giải mã XOR 0x3B (sub_401190)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C dịch ngược hàm sub_401190 trong Lab13-01.exe bằng Hex-Rays. Mã giả thể hiện rõ vòng lặp for: *(_BYTE *)(i + a1) ^= 0x3Bu;. Góc dưới phải ghi nhận thông báo Storage Sense từ Windows 10 thực.",
      "observation": "Mã giả thể hiện rõ vòng lặp for: *(_BYTE *)(i + a1) ^= 0x3Bu;. Góc dưới phải ghi nhận thông báo Storage Sense từ Windows 10 thực.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-04",
      "sampleId": "lab13-01",
      "tool": "IDA Pro 9.4",
      "imagePath": "evidence/04-ida-lab01-http-hostname.png",
      "title": "Cấu trúc hàm gửi HTTP Beacon C2 (sub_4011C9)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Khung đôi trong IDA Pro: Khung trên là XOR 0x3B, khung dưới là hàm sub_4011C9. Khai báo các biến WinINet API: HINTERNET hFile, HINTERNET hInternet, CHAR szUrl[512] chuẩn bị gửi request beacon tới máy chủ C2.",
      "observation": "Khai báo các biến WinINet API: HINTERNET hFile, HINTERNET hInternet, CHAR szUrl[512] chuẩn bị gửi request beacon tới máy chủ C2.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-05",
      "sampleId": "shared",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/05-procmon-process-filter.png",
      "title": "Cấu hình bộ lọc Process Monitor Filter",
      "kind": "dynamic",
      "status": "Thiết lập thu thập",
      "resolution": "2560x1600",
      "description": "Hộp thoại thiết lập quy tắc lọc sự kiện trong Process Monitor. Bộ lọc Include theo Process Name Lab13-01.exe, Lab13-02.exe, Lab13-03.exe. Đây là cấu hình thu thập; chưa phải một sự kiện chứng minh hành vi malware.",
      "observation": "Bộ lọc Include theo Process Name Lab13-01.exe, Lab13-02.exe, Lab13-03.exe. Đây là cấu hình thu thập; chưa phải một sự kiện chứng minh hành vi malware.",
      "sampleName": "Dùng chung"
    },
    {
      "id": "EVID-06",
      "sampleId": "lab13-02",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/06-procmon-lab02-runtime.png",
      "title": "Nhật ký hành vi thời gian thực của Lab13-02.exe (PID 3556)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Danh sách 845 sự kiện hệ thống ghi nhận từ tiến trình Lab13-02.exe. Ghi nhận Process Start từ Parent PID 5860, Thread Create (TID 4684), nạp ntdll.dll, wow64.dll và truy vấn Prefetch/Registry.",
      "observation": "Ghi nhận Process Start từ Parent PID 5860, Thread Create (TID 4684), nạp ntdll.dll, wow64.dll và truy vấn Prefetch/Registry.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-07",
      "sampleId": "lab13-02",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/07-procmon-lab02-writefile.png",
      "title": "Chi tiết thuộc tính tiến trình: Sự kiện Process Start (PID 3556)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Hộp thoại Event Properties trong Process Monitor của Lab13-02.exe. Ghi nhận sự kiện khởi chạy Process Start: Parent PID 5860, Command line C:\\Lab13Analysis\\samples\\Lab13-02.exe, Current directory C:\\Lab13Analysis\\runtime (không phải thao tác WriteFile).",
      "observation": "Ghi nhận sự kiện khởi chạy Process Start: Parent PID 5860, Command line C:\\Lab13Analysis\\samples\\Lab13-02.exe, Current directory C:\\Lab13Analysis\\runtime (không phải thao tác WriteFile).",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-08",
      "sampleId": "lab13-02",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/08-procmon-lab02-writefile-filtered.png",
      "title": "Ghi nhận thao tác WriteFile file mã hóa temp002a9d1e (5,436,114 bytes)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Dòng sự kiện Process Monitor lọc thao tác ghi file của Lab13-02.exe. Tiến trình Lab13-02.exe (PID 3556) thực hiện WriteFile thành công vào tệp C:\\Lab13Analysis\\runtime\\temp002a9d1e với độ dài chính xác 5,436,114 bytes.",
      "observation": "Tiến trình Lab13-02.exe (PID 3556) thực hiện WriteFile thành công vào tệp C:\\Lab13Analysis\\runtime\\temp002a9d1e với độ dài chính xác 5,436,114 bytes.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-09",
      "sampleId": "lab13-01",
      "tool": "Burp Suite Professional v2023.4.2",
      "imagePath": "evidence/09-burp-lab01-http-request.png",
      "title": "Burp Suite bắt trọn gói tin HTTP Beacon chứa Base64 Hostname",
      "kind": "dynamic",
      "status": "Quan sát mạng loopback",
      "resolution": "2560x1600",
      "description": "Giao diện HTTP History trong Burp Suite Professional v2023.4.2. Request HTTP GET /REVTS1RPUC1WNVZD/ gửi tới Host www.practicalmalwareanalysis.com, User-Agent Mozilla/4.0. Chuỗi REVTS1RPUC1WNVZD là mã hóa Base64 chuẩn của 12 ký tự đầu hostname DESKTOP-V5VC (từ DESKTOP-V5VC9B3). Cột IP ghi nhận 127.0.0.1 và phản hồi có nội dung \"lab13-local-observation\", thể hiện việc đánh chặn và mô phỏng phản hồi C2 trong môi trường loopback cô lập cục bộ, không gửi gói tin ra Internet.",
      "observation": "Request HTTP GET /REVTS1RPUC1WNVZD/ gửi tới Host www.practicalmalwareanalysis.com, User-Agent Mozilla/4.0. Chuỗi REVTS1RPUC1WNVZD là mã hóa Base64 chuẩn của 12 ký tự đầu hostname DESKTOP-V5VC (từ DESKTOP-V5VC9B3). Cột IP ghi nhận 127.0.0.1 và phản hồi có nội dung \"lab13-local-observation\", thể hiện việc đánh chặn và mô phỏng phản hồi C2 trong môi trường loopback cô lập cục bộ, không gửi gói tin ra Internet.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-10",
      "sampleId": "lab13-02",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/10-ida-lab02-screen-capture.png",
      "title": "Mã giả hàm chụp màn hình GDI Desktop (sub_401070)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả dịch ngược C hàm sub_401070 trong Lab13-02.exe. Sử dụng GetSystemMetrics(0/1) lấy kích thước, GetDesktopWindow, GetDC, CreateCompatibleDC, BitBlt (mã ROP 0xCC0020u = SRCCOPY) sao chép toàn bộ màn hình và gán biBitCount = 32 cho cấu trúc BMP.",
      "observation": "Sử dụng GetSystemMetrics(0/1) lấy kích thước, GetDesktopWindow, GetDC, CreateCompatibleDC, BitBlt (mã ROP 0xCC0020u = SRCCOPY) sao chép toàn bộ màn hình và gán biBitCount = 32 cho cấu trúc BMP.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-11",
      "sampleId": "lab13-02",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/11-ida-lab02-encrypt-write.png",
      "title": "Luồng điều phối Chụp - Mã hóa - Ghi đĩa (sub_401851)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm điều phối trung tâm sub_401851 trong Lab13-02.exe. Gọi sub_401070 chụp màn hình, sub_40181F mã hóa Rabbit, GetTickCount() định dạng chuỗi temp%08x và gọi sub_401000 ghi file ra thư mục làm việc hiện tại.",
      "observation": "Gọi sub_401070 chụp màn hình, sub_40181F mã hóa Rabbit, GetTickCount() định dạng chuỗi temp%08x và gọi sub_401000 ghi file ra thư mục làm việc hiện tại.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-12",
      "sampleId": "lab13-02",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/12-ida-lab02-rabbit-constants.png",
      "title": "Hằng số Counter thuật toán Rabbit hiển thị ở dạng Decimal (sub_4012DD)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm sinh trạng thái Rabbit sub_4012DD trong Lab13-02.exe. Hex-Rays hiển thị hằng số cập nhật counter ở hệ thập phân (decimal): 1295307613 (tương ứng 0x4D34D35D), -749914925 (tương ứng 0xD34D34D3), 886263092 (tương ứng 0x34D34D34).",
      "observation": "Hex-Rays hiển thị hằng số cập nhật counter ở hệ thập phân (decimal): 1295307613 (tương ứng 0x4D34D35D), -749914925 (tương ứng 0xD34D34D3), 886263092 (tương ứng 0x34D34D34).",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-13",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/13-ida-lab03-c2-connect.png",
      "title": "Hàm _main: Khởi tạo khóa mã hóa và kết nối C2 Port 8910",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm _main (0x00401879) trong Lab13-03.exe. Hàm _main gọi sub_401AC2 với symbol tự động aijklmnopqrstuv (tên nhãn IDA tự gán dựa trên chuỗi) để nạp khóa khối 16-byte thực tế \"ijklmnopqrstuvwx\" (VA 0x00412208). Tiếp đó khởi tạo Winsock WSASocketA, thiết lập port 8910 (htons 0x22CEu), gọi connect tới C2 và kích hoạt luồng reverse shell sub_4015B7.",
      "observation": "Hàm _main gọi sub_401AC2 với symbol tự động aijklmnopqrstuv (tên nhãn IDA tự gán dựa trên chuỗi) để nạp khóa khối 16-byte thực tế \"ijklmnopqrstuvwx\" (VA 0x00412208). Tiếp đó khởi tạo Winsock WSASocketA, thiết lập port 8910 (htons 0x22CEu), gọi connect tới C2 và kích hoạt luồng reverse shell sub_4015B7.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-14",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/14-ida-lab03-pipes-cmd.png",
      "title": "Khai báo cấu trúc Pipe và Process (sub_4015B7)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Đầu hàm sub_4015B7 trong Lab13-03.exe thể hiện danh sách biến ngăn xếp. Khai báo các biến quản lý đường ống nặc danh (hReadPipe, hWritePipe), STARTUPINFOA, PROCESS_INFORMATION và lệnh dự phòng strcpy(v23, \"dir\\n\"); chuẩn bị cho quá trình tạo pipe chuyển hướng.",
      "observation": "Khai báo các biến quản lý đường ống nặc danh (hReadPipe, hWritePipe), STARTUPINFOA, PROCESS_INFORMATION và lệnh dự phòng strcpy(v23, \"dir\\n\"); chuẩn bị cho quá trình tạo pipe chuyển hướng.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-15",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/15-ida-lab03-outbound-encryption.png",
      "title": "Luồng mã hóa Outbound gửi dữ liệu shell về C2 (sub_40132B)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm luồng worker gửi dữ liệu sub_40132B trong Lab13-03.exe. Vòng lặp ReadFile đọc dữ liệu đầu ra từ pipe stdout của cmd.exe, gọi hàm mã hóa sub_40352D với hướng mã hóa (flag=1), rồi ghi dữ liệu mã hóa ra socket mạng bằng WriteFile.",
      "observation": "Vòng lặp ReadFile đọc dữ liệu đầu ra từ pipe stdout của cmd.exe, gọi hàm mã hóa sub_40352D với hướng mã hóa (flag=1), rồi ghi dữ liệu mã hóa ra socket mạng bằng WriteFile.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-16",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/16-ida-lab03-inbound-decode.png",
      "title": "Luồng giải mã Inbound lệnh Base64 nhận từ C2 (StartAddress)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm luồng worker nhận lệnh StartAddress (0x0040147C) trong Lab13-03.exe. Vòng lặp ReadFile nhận dữ liệu Base64 từ socket mạng, gọi hàm giải mã sub_401082 (bảng Base64 tùy biến bắt đầu bằng ký tự C: C-ZABc-zab0-9+/), rồi đẩy lệnh plaintext sau giải mã vào pipe stdin của cmd.exe.",
      "observation": "Vòng lặp ReadFile nhận dữ liệu Base64 từ socket mạng, gọi hàm giải mã sub_401082 (bảng Base64 tùy biến bắt đầu bằng ký tự C: C-ZABc-zab0-9+/), rồi đẩy lệnh plaintext sau giải mã vào pipe stdin của cmd.exe.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-18",
      "sampleId": "lab13-03",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/18-procmon-lab03-cmd-child.png",
      "title": "Ghi nhận Lab13-03.exe tạo tiến trình con cmd.exe và conhost.exe",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Danh sách sự kiện Process Create trong Process Monitor. Tiến trình Lab13-03.exe (PID 4336) thực hiện Process Create thành công conhost.exe (PID 712) và cmd.exe (PID 4532, Command line: cmd.exe).",
      "observation": "Tiến trình Lab13-03.exe (PID 4336) thực hiện Process Create thành công conhost.exe (PID 712) và cmd.exe (PID 4532, Command line: cmd.exe).",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-19",
      "sampleId": "lab13-02",
      "tool": "HxD Hex Editor",
      "imagePath": "evidence/19-hxd-lab02-encrypted-file.png",
      "title": "Kiểm tra tệp mã hóa temp002a9d1e trong HxD Hex Editor",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Giao diện HxD Hex Editor mở tệp C:\\Lab13Analysis\\runtime\\temp002a9d1e trong máy ảo. Offset 00000000 bắt đầu bằng chuỗi byte: E2 EE 44 DE 21 CC 46 27 34 ED 92 74 F1 60 F6 42. Hai byte đầu E2 EE khớp hoàn toàn với kết quả XOR giữa BM (0x42 0x4D) và keystream Rabbit (0xA0 0xA3).",
      "observation": "Offset 00000000 bắt đầu bằng chuỗi byte: E2 EE 44 DE 21 CC 46 27 34 ED 92 74 F1 60 F6 42. Hai byte đầu E2 EE khớp hoàn toàn với kết quả XOR giữa BM (0x42 0x4D) và keystream Rabbit (0xA0 0xA3).",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-20",
      "sampleId": "lab13-02",
      "tool": "HxD Hex Editor",
      "imagePath": "evidence/20-hxd-lab02-decrypted-bmp.png",
      "title": "Cấu trúc tệp BMP giải mã trong HxD Hex Editor",
      "kind": "dynamic",
      "status": "Đối chiếu artifact giải mã",
      "resolution": "2560x1600",
      "description": "Giao diện HxD Hex Editor mở tệp C:\\Lab13Analysis\\artifacts\\recovered.bmp. Xác nhận cấu trúc BMP hợp lệ: Magic 42 4D (BM), kích thước tệp bfSize = 0x0052F2D2 (5,436,114 bytes), biWidth = 1505 (0x05E1), biHeight = 903 (0x0387), biBitCount = 32 (0x20).",
      "observation": "Xác nhận cấu trúc BMP hợp lệ: Magic 42 4D (BM), kích thước tệp bfSize = 0x0052F2D2 (5,436,114 bytes), biWidth = 1505 (0x05E1), biHeight = 903 (0x0387), biBitCount = 32 (0x20).",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-21",
      "sampleId": "lab13-02",
      "tool": "Microsoft Paint",
      "imagePath": "evidence/21-paint-lab02-recovered-screen.png",
      "title": "Hiển thị ảnh màn hình giải mã thành công trong MS Paint",
      "kind": "dynamic",
      "status": "Đối chiếu artifact giải mã",
      "resolution": "2560x1600",
      "description": "Ứng dụng Microsoft Paint mở tệp recovered.bmp trong môi trường Windows 10. Paint hiển thị hình ảnh màn hình desktop chứa cửa sổ Process Monitor. Thanh trạng thái Paint xác nhận kích thước 1505 x 903 px, dung lượng 5.2MB.",
      "observation": "Paint hiển thị hình ảnh màn hình desktop chứa cửa sổ Process Monitor. Thanh trạng thái Paint xác nhận kích thước 1505 x 903 px, dung lượng 5.2MB.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-22",
      "sampleId": "lab13-03",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/22-procmon-cmd-process-properties.png",
      "title": "Chi tiết quan hệ Cha - Con: Lab13-03.exe sinh cmd.exe (PID 4532)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Hộp thoại Event Properties chi tiết của sự kiện Process Create cmd.exe. Tiến trình cha Lab13-03.exe (PID 4336) tạo tiến trình con cmd.exe (PID 4532). Nền phía sau hiển thị sự kiện Process Start của cmd.exe với Parent PID 4336.",
      "observation": "Tiến trình cha Lab13-03.exe (PID 4336) tạo tiến trình con cmd.exe (PID 4532). Nền phía sau hiển thị sự kiện Process Start của cmd.exe với Parent PID 4336.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-23",
      "sampleId": "shared",
      "tool": "HashMyFiles (NirSoft)",
      "imagePath": "evidence/23-hashmyfiles-samples.png",
      "title": "Bảng mã băm toàn vẹn (MD5 & SHA-256) của 3 mẫu Chapter 13",
      "kind": "static",
      "status": "Kiểm tra toàn vẹn",
      "resolution": "2560x1600",
      "description": "Giao diện công cụ HashMyFiles tính toán mã băm trong máy ảo Windows 10. Hiển thị mã MD5 và SHA-256 tính toán trực tiếp trong máy ảo, đối chiếu khớp chính xác với bản sao nhị phân dùng đối chiếu: Lab13-01.exe (SHA-256: 71a29524...), Lab13-02.exe (SHA-256: 598f21f1...), Lab13-03.exe (SHA-256: 86054002...).",
      "observation": "Hiển thị mã MD5 và SHA-256 tính toán trực tiếp trong máy ảo, đối chiếu khớp chính xác với bản sao nhị phân dùng đối chiếu: Lab13-01.exe (SHA-256: 71a29524...), Lab13-02.exe (SHA-256: 598f21f1...), Lab13-03.exe (SHA-256: 86054002...).",
      "sampleName": "Dùng chung"
    },
    {
      "id": "EVID-24",
      "sampleId": "lab13-03",
      "tool": "Process Hacker",
      "imagePath": "evidence/24-processhacker-live-lab03.png",
      "title": "Cây tiến trình Process Hacker: Lab13-03.exe hoạt động (PID 5188)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Danh sách tiến trình hoạt động lọc theo từ khóa Lab13 trong Process Hacker. Ghi nhận tiến trình Lab13-03.exe đang thực thi với PID 5188. Trong snapshot cụ thể này, tiến trình không hiển thị tiến trình con nào đang phân nhánh bên dưới.",
      "observation": "Ghi nhận tiến trình Lab13-03.exe đang thực thi với PID 5188. Trong snapshot cụ thể này, tiến trình không hiển thị tiến trình con nào đang phân nhánh bên dưới.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-25",
      "sampleId": "lab13-03",
      "tool": "Process Hacker",
      "imagePath": "evidence/25-processhacker-live-tcp8910.png",
      "title": "Kết nối mạng TCP Established tới Port 8910 trong Process Hacker",
      "kind": "dynamic",
      "status": "Quan sát mạng loopback",
      "resolution": "2560x1600",
      "description": "Tab Network trong Process Hacker hiển thị trạng thái kết nối mạng của tiến trình. Lab13-03.exe (PID 5188) duy trì kết nối TCP trạng thái Established tới cổng đích 8910 (Local port 49774). Nhật ký JSON thô trước đó ghi nhận phiên chạy sớm hơn với PID 4336 (Local port 49747); ảnh này thể hiện một phiên thực thi riêng biệt sau đó nhưng cùng tái lập kết nối outbound tới port 8910. Không tuyên bố có lệnh từ xa nào được gửi hoặc thực thi trong phiên chụp.",
      "observation": "Lab13-03.exe (PID 5188) duy trì kết nối TCP trạng thái Established tới cổng đích 8910 (Local port 49774). Nhật ký JSON thô trước đó ghi nhận phiên chạy sớm hơn với PID 4336 (Local port 49747); ảnh này thể hiện một phiên thực thi riêng biệt sau đó nhưng cùng tái lập kết nối outbound tới port 8910. Không tuyên bố có lệnh từ xa nào được gửi hoặc thực thi trong phiên chụp.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-26",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/26-ida-lab03-createpipes.png",
      "title": "Khởi tạo 2 Anonymous Pipes và DuplicateHandle trong sub_4015B7",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C dịch ngược hàm sub_4015B7 trong Lab13-03.exe. Gọi CreatePipe hai lần (&hReadPipe, &hWritePipe và &hObject, &hSourceHandle) để tạo hai cặp đường ống nặc danh, sau đó gọi DuplicateHandle sao chép handle với quyền thừa kế phục vụ chuyển hướng I/O.",
      "observation": "Gọi CreatePipe hai lần (&hReadPipe, &hWritePipe và &hObject, &hSourceHandle) để tạo hai cặp đường ống nặc danh, sau đó gọi DuplicateHandle sao chép handle với quyền thừa kế phục vụ chuyển hướng I/O.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-27",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/27-ida-lab03-redirect-createprocess.png",
      "title": "Chuyển hướng Standard Handles và gọi CreateProcessA (sub_4015B7)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C phần thiết lập tiến trình con trong sub_4015B7. Gán StartupInfo.hStdInput = hObject, StartupInfo.hStdOutput = hWritePipe, StartupInfo.hStdError = hWritePipe, bật cờ STARTF_USESTDHANDLES (0x100) và gọi CreateProcessA với biến CommandLine để kích hoạt shell.",
      "observation": "Gán StartupInfo.hStdInput = hObject, StartupInfo.hStdOutput = hWritePipe, StartupInfo.hStdError = hWritePipe, bật cờ STARTF_USESTDHANDLES (0x100) và gọi CreateProcessA với biến CommandLine để kích hoạt shell.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-28",
      "sampleId": "lab13-01",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/28-ida-lab01-loop-exit-delay.png",
      "title": "Vòng lặp main beacon và độ trễ thoát 30 giây (sub_4013ed)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm main sub_4013ed trong Lab13-01.exe hiển thị quy trình gọi Sleep trước và sau lượt gửi HTTP beacon. Hàm sub_4013ed gọi Sleep(500) trước beacon, gọi sub_4011c9 gửi HTTP GET, và luôn gọi Sleep(30000) (30 giây) vô điều kiện ngay sau beacon. Phép kiểm tra cờ thoát chỉ diễn ra sau giấc ngủ 30 giây này.",
      "observation": "Hàm sub_4013ed gọi Sleep(500) trước beacon, gọi sub_4011c9 gửi HTTP GET, và luôn gọi Sleep(30000) (30 giây) vô điều kiện ngay sau beacon. Phép kiểm tra cờ thoát chỉ diễn ra sau giấc ngủ 30 giây này.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-29",
      "sampleId": "lab13-01",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/29-ida-lab01-response-o.png",
      "title": "Phần đầu hàm sub_4011c9 lấy hostname và khởi tạo WinINet (Tên file cũ nhầm response-o)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C phần đầu của hàm sub_4011c9 trong Lab13-01.exe. Tệp ảnh bị đặt tên nhầm là response-o nhưng nội dung thực tế không hiển thị lệnh so sánh \"o\". Ảnh chỉ hiển thị đoạn đầu hàm sub_4011c9 với các API gethostname, cắt ngắn 12 ký tự và khởi tạo WinINet (InternetOpenA, InternetOpenUrlA). Không hiển thị lệnh so sánh ký tự phản hồi \"o\" (Buffer[0] == 111); tiêu đề được hiệu chỉnh chính xác theo nội dung hiển thị thực tế.",
      "observation": "Ảnh chỉ hiển thị đoạn đầu hàm sub_4011c9 với các API gethostname, cắt ngắn 12 ký tự và khởi tạo WinINet (InternetOpenA, InternetOpenUrlA). Không hiển thị lệnh so sánh ký tự phản hồi \"o\" (Buffer[0] == 111); tiêu đề được hiệu chỉnh chính xác theo nội dung hiển thị thực tế.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-30",
      "sampleId": "lab13-01",
      "tool": "IDA Pro 9.4",
      "imagePath": "evidence/30-ida-lab01-base64-alphabet.png",
      "title": "Một phần bảng ký tự Base64 chuẩn trong IDA Pro (VA 0x004050e8)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Giao diện IDA Pro hiển thị dữ liệu bảng ký tự Base64 chuẩn của Lab13-01.exe tại địa chỉ VA 0x004050e8. Giao diện IDA Pro chỉ hiển thị một phần bảng ký tự (partial alphabet: A..Z, a..); chưa bao quát toàn bộ 64 ký tự (thiếu phần chữ số và ký hiệu +/) trên khung hình này.",
      "observation": "Giao diện IDA Pro chỉ hiển thị một phần bảng ký tự (partial alphabet: A..Z, a..); chưa bao quát toàn bộ 64 ký tự (thiếu phần chữ số và ký hiệu +/) trên khung hình này.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-31",
      "sampleId": "lab13-01",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/31-ida-lab01-response-o-comparison.png",
      "title": "Điều kiện kiểm tra byte đầu phản hồi C2 bằng \"o\" (Buffer[0] == 111)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C phần cuối hàm sub_4011c9 trong Lab13-01.exe hiển thị phép so sánh byte đầu tiên của nội dung phản hồi từ C2. Mã giả C xác nhận rõ điều kiện Buffer[0] == 111 (111 là mã ASCII của ký tự \"o\"). Nếu khớp, hàm trả về giá trị 1 để báo hiệu cho hàm main tiến hành thoát tiến trình sau giấc ngủ 30s.",
      "observation": "Mã giả C xác nhận rõ điều kiện Buffer[0] == 111 (111 là mã ASCII của ký tự \"o\"). Nếu khớp, hàm trả về giá trị 1 để báo hiệu cho hàm main tiến hành thoát tiến trình sau giấc ngủ 30s.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-32",
      "sampleId": "lab13-01",
      "tool": "Burp Suite Professional v2023.4.2",
      "imagePath": "evidence/32-burp-lab01-response-o.png",
      "title": "Burp Suite ghi nhận phản hồi HTTP 200 chứa ký tự \"o\" điều khiển thoát",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Giao diện Burp Suite Professional v2023.4.2 hiển thị chi tiết request HTTP GET beacon và response điều khiển thoát từ server. Burp Suite ghi nhận request GET /REVTS1RPUC1WNVZD/ và phản hồi HTTP 200 OK thực tế từ máy chủ cục bộ có Content-Length: 1 và thân thông điệp (body) chứa đúng một ký tự \"o\".",
      "observation": "Burp Suite ghi nhận request GET /REVTS1RPUC1WNVZD/ và phản hồi HTTP 200 OK thực tế từ máy chủ cục bộ có Content-Length: 1 và thân thông điệp (body) chứa đúng một ký tự \"o\".",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-33",
      "sampleId": "lab13-02",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/33-ida-lab02-sleep5000.png",
      "title": "Hai lệnh Sleep(5000) trong vòng lặp vô hạn hàm main (sub_4018d8)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm _main (0x004018D8) của Lab13-02.exe hiển thị vòng lặp vô tận chụp và mã hóa màn hình desktop. Hàm _main chứa 2 lệnh gọi Sleep(5000) (hai lần ngủ 5 giây) xen kẽ giữa các lần gọi hàm worker sub_401851 (chụp màn hình, mã hóa Rabbit và ghi file temp%08x), giải thích chu kỳ ghi file thực tế ~10 giây.",
      "observation": "Hàm _main chứa 2 lệnh gọi Sleep(5000) (hai lần ngủ 5 giây) xen kẽ giữa các lần gọi hàm worker sub_401851 (chụp màn hình, mã hóa Rabbit và ghi file temp%08x), giải thích chu kỳ ghi file thực tế ~10 giây.",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-34",
      "sampleId": "lab13-02",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/34-ida-lab02-zero-state.png",
      "title": "Khởi tạo ngữ cảnh Rabbit Cipher về 0 (Zero-State 68 bytes)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm sub_40181f trong Lab13-02.exe hiển thị việc thiết lập vùng nhớ ngữ cảnh cho thuật toán Rabbit Stream Cipher. Hàm sub_40181f gọi memset(&ctx, 0, 0x44) khởi tạo toàn bộ 68 bytes ngữ cảnh về 0, chứng minh thuật toán sử dụng zero-state mà không có thủ tục thiết lập khóa (key schedule) hay vòng quay khởi động (warmup).",
      "observation": "Hàm sub_40181f gọi memset(&ctx, 0, 0x44) khởi tạo toàn bộ 68 bytes ngữ cảnh về 0, chứng minh thuật toán sử dụng zero-state mà không có thủ tục thiết lập khóa (key schedule) hay vòng quay khởi động (warmup).",
      "sampleName": "Lab13-02.exe"
    },
    {
      "id": "EVID-35",
      "sampleId": "lab13-03",
      "tool": "Hex-Rays Decompiler (IDA Pro 9.4)",
      "imagePath": "evidence/35-ida-lab03-cbc-feedback.png",
      "title": "Cơ chế mã hóa AES-128-CBC và duy trì Feedback Block (sub_40352d)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Mã giả C hàm sub_40352d trong Lab13-03.exe thể hiện cấu trúc mã hóa khối AES ở chế độ CBC. Vòng lặp mã hóa gọi sub_403990 thực hiện XOR plaintext với feedback block tại 0x004035DB, gọi hàm lõi AES sub_402DA8 tại 0x004035F1, và gọi memcpy sao chép ciphertext vào feedback buffer context+0x3F4 tại 0x0040360D. Căn cứ thuần túy phân tích tĩnh, không tự động suy diễn đã có thực thi mã hóa AES runtime.",
      "observation": "Vòng lặp mã hóa gọi sub_403990 thực hiện XOR plaintext với feedback block tại 0x004035DB, gọi hàm lõi AES sub_402DA8 tại 0x004035F1, và gọi memcpy sao chép ciphertext vào feedback buffer context+0x3F4 tại 0x0040360D. Căn cứ thuần túy phân tích tĩnh, không tự động suy diễn đã có thực thi mã hóa AES runtime.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-36",
      "sampleId": "lab13-03",
      "tool": "IDA Pro 9.4",
      "imagePath": "evidence/36-ida-lab03-custom-base64.png",
      "title": "Bảng ký tự Custom Base64 dịch chuyển bắt đầu bằng \"C\" (VA 0x004120a4)",
      "kind": "static",
      "status": "Phân tích tĩnh",
      "resolution": "2560x1600",
      "description": "Giao diện IDA Pro hiển thị trọn vẹn chuỗi bảng ký tự Custom Base64 của Lab13-03.exe tại địa chỉ VA 0x004120a4. Bảng ký tự đầy đủ bắt đầu bằng byte 43h (\"C\"), dịch chuyển 2 vị trí: CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/. Đây là bảng giải mã cho luồng Inbound nhận lệnh từ C2.",
      "observation": "Bảng ký tự đầy đủ bắt đầu bằng byte 43h (\"C\"), dịch chuyển 2 vị trí: CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/. Đây là bảng giải mã cho luồng Inbound nhận lệnh từ C2.",
      "sampleName": "Lab13-03.exe"
    },
    {
      "id": "EVID-37",
      "sampleId": "lab13-01",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/37-procmon-lab01-natural-exit.png",
      "title": "Procmon ghi nhận Lab13-01.exe kết thúc tự nhiên (Exit Status 0)",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Process Monitor v3.96 ghi nhận sự kiện Process Exit của tiến trình Lab13-01.exe sau khi nhận phản hồi C2. Tiến trình Lab13-01.exe (PID 4992) thực hiện sự kiện Process Exit với Exit Status: 0 tại mốc thời gian 20:37:29.0234778, xác nhận phản hồi chứa ký tự \"o\" kích hoạt cơ chế kết thúc tự nhiên sau giấc ngủ 30 giây.",
      "observation": "Tiến trình Lab13-01.exe (PID 4992) thực hiện sự kiện Process Exit với Exit Status: 0 tại mốc thời gian 20:37:29.0234778, xác nhận phản hồi chứa ký tự \"o\" kích hoạt cơ chế kết thúc tự nhiên sau giấc ngủ 30 giây.",
      "sampleName": "Lab13-01.exe"
    },
    {
      "id": "EVID-38",
      "sampleId": "lab13-02",
      "tool": "Process Monitor v3.96",
      "imagePath": "evidence/38-procmon-lab02-ten-second-interval.png",
      "title": "Procmon ghi nhận Lab13-02.exe ghi 2 file ảnh cách nhau 10.22 giây",
      "kind": "dynamic",
      "status": "Quan sát thực nghiệm",
      "resolution": "2560x1600",
      "description": "Process Monitor v3.96 lọc sự kiện WriteFile của tiến trình Lab13-02.exe (PID 3876). Tiến trình Lab13-02.exe (PID 3876) thực hiện 2 sự kiện WriteFile liên tiếp ghi đúng 5.461.422 bytes mỗi file, thời điểm ghi cách nhau 10.2218796 giây, khớp với chu kỳ 2 lần Sleep(5000) trong mã máy.",
      "observation": "Tiến trình Lab13-02.exe (PID 3876) thực hiện 2 sự kiện WriteFile liên tiếp ghi đúng 5.461.422 bytes mỗi file, thời điểm ghi cách nhau 10.2218796 giây, khớp với chu kỳ 2 lần Sleep(5000) trong mã máy.",
      "sampleName": "Lab13-02.exe"
    }
  ],
  "readingGuide": {
    "overview": [
      {
        "id": "overview-identify",
        "title": "Xác định đúng ba mẫu trước khi phân tích",
        "explanation": "Bài thực hành thuộc folder 13, gồm Lab13-01.exe, Lab13-02.exe và Lab13-03.exe. Mã băm là dấu vân tay của tệp: dùng để đối chiếu mẫu giữa các công cụ, không tự chứng minh tệp có hành vi độc hại. Ảnh HashMyFiles bên dưới là bằng chứng nhận diện, chưa phải bằng chứng thực thi.",
        "evidence": [
          {
            "id": "EVID-23",
            "where": "Ba dòng tên Lab13-01.exe, Lab13-02.exe, Lab13-03.exe và các cột MD5, SHA-256 trong cửa sổ HashMyFiles.",
            "conclusion": "Nhận diện đúng bộ mẫu Chapter 13. Hash đầy đủ của từng mẫu nằm trong mục thông tin kỹ thuật ở cuối trang phân tích tương ứng."
          }
        ],
        "takeaway": "Nhận diện mẫu trước; sau đó mới dùng mã máy và sự kiện thực nghiệm để giải thích hành vi.",
        "narration": "Em trình bày ba mẫu thuộc folder 13 của Practical Malware Analysis. Trước tiên là ảnh HashMyFiles để xác định đúng các tệp đang phân tích. Mã băm giúp đối chiếu mẫu, còn kết luận về hành vi sẽ dựa vào IDA và các công cụ giám sát ở những phần tiếp theo."
      },
      {
        "id": "overview-method",
        "title": "Phân biệt mã máy, hành vi đã chạy và kết quả khôi phục",
        "explanation": "Phân tích tĩnh đọc mã máy bằng IDA để biết chương trình được thiết kế làm gì. Phân tích động dùng Burp, Procmon và Process Hacker để ghi nhận điều thực sự xảy ra trong từng phiên chạy. HxD và Paint dùng kiểm tra tệp ảnh được khôi phục. Bộ lọc Procmon dưới đây chỉ xác định phạm vi thu thập, không phải một hành vi malware.",
        "evidence": [
          {
            "id": "EVID-05",
            "where": "Hộp thoại Process Monitor Filter: các điều kiện Process Name cho ba mẫu Lab13, hành động Include.",
            "conclusion": "Procmon được cấu hình theo dõi ba mẫu. Muốn chứng minh ghi tệp, tạo tiến trình hay kết nối phải xem sự kiện cụ thể, không dùng riêng ảnh bộ lọc."
          }
        ],
        "takeaway": "Mỗi phần tiếp theo đi theo cùng một nhịp: giải thích cơ chế, đọc ảnh ngay bên dưới, rồi chốt phạm vi chứng minh. Không cần chuyển sang kho ảnh.",
        "narration": "Bài này kết hợp phân tích tĩnh và phân tích động. IDA giải thích cơ chế trong mã máy; Burp và Procmon đối chiếu hành vi khi chạy. Ở đây là cấu hình bộ lọc Procmon, chưa phải kết quả phát hiện. Các ảnh tiếp theo được đặt ngay dưới nhận định tương ứng để người xem đối chiếu trực tiếp."
      }
    ],
    "lab13-01": [
      {
        "id": "lab01-domain",
        "title": "Địa chỉ máy chủ được giấu bằng XOR như thế nào?",
        "explanation": "Mẫu đầu tiên là beacon HTTP: chương trình gửi thông tin nhận diện máy về một địa chỉ điều khiển. Domain không nằm ở dạng chuỗi rõ thông thường; Resource 101 chứa 32 byte, được XOR từng byte với khóa 0x3B để thu được www.practicalmalwareanalysis.com. Hai ảnh IDA dưới đây cho thấy cùng một vòng lặp ở dạng assembly và mã giả.",
        "evidence": [
          {
            "id": "EVID-02",
            "where": "Hàm sub_401190: lệnh xor eax, 3Bh, sau đó mov [ecx], al trong vòng lặp.",
            "conclusion": "Mỗi byte được biến đổi bằng cùng khóa XOR 0x3B. Ảnh chứng minh phép biến đổi; raw Resource 101 và kết quả domain được đối chiếu trong dữ liệu xuất, không hiển thị đầy đủ trong ảnh này."
          },
          {
            "id": "EVID-03",
            "where": "Cửa sổ mã giả Hex-Rays: biểu thức *(_BYTE *)(i + a1) ^= 0x3Bu bên trong vòng for.",
            "conclusion": "Mã giả xác nhận cách đọc assembly của ảnh trước. Đây là che giấu chuỗi bằng XOR một byte, không phải mã hóa AES."
          }
        ],
        "takeaway": "XOR 0x3B dùng cho domain trong resource. Không áp phép XOR này cho hostname ở bước tiếp theo.",
        "narration": "Lab13-01 là một beacon HTTP. Ảnh assembly cho thấy vòng lặp XOR với khóa 0x3B; ảnh mã giả ngay dưới thể hiện cùng phép biến đổi rõ hơn. Đối chiếu Resource 101 thu được domain www.practicalmalwareanalysis.com. Phép XOR này dành cho domain, không phải hostname của máy."
      },
      {
        "id": "lab01-hostname",
        "title": "Hostname được đưa vào URL bằng Base64 chuẩn",
        "explanation": "Chương trình gọi gethostname, sao chép tối đa 12 byte đầu rồi thêm ký tự kết thúc chuỗi. Hostname trong lab là DESKTOP-V5VC9B3; 12 byte được sử dụng là DESKTOP-V5VC. Base64 chuẩn của phần này là REVTS1RPUC1WNVZD. Base64 là cách biểu diễn dữ liệu, không phải thuật toán giữ bí mật nội dung.",
        "evidence": [
          {
            "id": "EVID-29",
            "where": "Phần đầu sub_4011C9: gethostname, sao chép giới hạn 12 ký tự và các lời gọi WinINet phía sau.",
            "conclusion": "Hostname được lấy và rút ngắn trước khi đưa vào URL. Tên tệp ảnh cũ có chữ response-o nhưng ảnh này không hiển thị điều kiện phản hồi o; điều kiện đó ở bước 4."
          },
          {
            "id": "EVID-30",
            "where": "Vùng dữ liệu tại VA 0x004050E8: đầu bảng chữ cái A–Z và phần chữ thường đang được IDA hiển thị.",
            "conclusion": "Ảnh cho thấy một phần alphabet. Kết luận Base64 chuẩn còn dựa vào đối chiếu đủ 64 byte trong dữ liệu xuất; không nói ảnh này chứa toàn bộ bảng."
          }
        ],
        "takeaway": "DESKTOP-V5VC được biểu diễn thành REVTS1RPUC1WNVZD. Chuỗi này là dấu nhận diện máy trong đường dẫn HTTP.",
        "narration": "Tiếp theo, mẫu lấy hostname và chỉ giữ 12 byte đầu. Với máy lab, phần đó là DESKTOP-V5VC, được biểu diễn Base64 thành chuỗi REVTS1RPUC1WNVZD. Ảnh IDA cho thấy đoạn lấy hostname và một phần bảng ký tự. Kết luận bảng chuẩn đã được đối chiếu với dữ liệu đầy đủ, không chỉ dựa vào phần đang nhìn thấy."
      },
      {
        "id": "lab01-http",
        "title": "Burp ghi nhận đúng request mà mã máy dự kiến",
        "explanation": "Hàm beacon dùng WinINet tạo HTTP GET với đường dẫn chứa hostname đã Base64. Trong thực nghiệm, domain được trỏ về dịch vụ kiểm tra cục bộ. Burp Suite Professional được mở từ shortcut Desktop theo cấu hình của máy ảo. Request trong ảnh là lưu lượng thật của mẫu tới môi trường mô phỏng, không phải bằng chứng liên lạc C2 ngoài Internet.",
        "evidence": [
          {
            "id": "EVID-04",
            "where": "Hàm sub_4011C9 trong IDA: các biến HINTERNET, hFile, hInternet và szUrl.",
            "conclusion": "Mã máy chuẩn bị phiên WinINet và URL cho beacon. Ảnh Burp ngay dưới đối chiếu phần lưu lượng thực tế."
          },
          {
            "id": "EVID-09",
            "where": "Burp HTTP history và request: GET /REVTS1RPUC1WNVZD/, Host www.practicalmalwareanalysis.com; IP đích ghi 127.0.0.1.",
            "conclusion": "Đã quan sát beacon mang thông tin hostname. Phản hồi trong phiên này là lab13-local-observation, không phải phản hồi o của lượt kiểm tra thoát."
          }
        ],
        "takeaway": "Mã máy và request khớp nhau: lấy hostname, Base64 rồi gửi qua HTTP. Đích thực nghiệm là localhost.",
        "narration": "Đến phần thực nghiệm, ảnh Burp ghi nhận GET với đúng đường dẫn Base64 vừa phân tích. Trường Host vẫn là domain trong mẫu, nhưng địa chỉ đích của bài lab là 127.0.0.1. Vì vậy đây là beacon được quan sát trong môi trường mô phỏng cục bộ, không phải kết nối ra máy chủ Internet."
      },
      {
        "id": "lab01-response",
        "title": "Phản hồi o yêu cầu kết thúc, nhưng vẫn còn lần ngủ 30 giây",
        "explanation": "Hàm beacon kiểm tra byte đầu của response có bằng 111 hay không; 111 là mã ASCII của chữ o. Hàm main gọi Sleep(500), gửi beacon, luôn Sleep(30000), sau đó mới xét cờ trả về. Vì vậy nhận o không làm tiến trình thoát ngay. Ba ảnh dưới nối điều kiện trong mã máy với phản hồi HTTP thật.",
        "evidence": [
          {
            "id": "EVID-28",
            "where": "Hàm main: Sleep(500), gọi sub_4011C9, Sleep(30000), rồi mới kiểm tra giá trị trả về.",
            "conclusion": "Có một lần ngủ 30 giây vô điều kiện sau beacon. Không được đảo thứ tự thành kiểm tra o rồi mới quyết định có ngủ hay không."
          },
          {
            "id": "EVID-31",
            "where": "Phần cuối sub_4011C9: biểu thức Buffer[0] == 111.",
            "conclusion": "Điều kiện điều khiển thoát là byte đầu bằng chữ o, không phải mã trạng thái HTTP 200 tự nó làm tiến trình thoát."
          },
          {
            "id": "EVID-32",
            "where": "Burp: HTTP 200 OK, Content-Length: 1 và body chỉ có ký tự o.",
            "conclusion": "Dịch vụ kiểm tra đã thực sự trả đúng byte điều khiển. Đây là lượt bổ sung, khác với response của ảnh 09."
          }
        ],
        "takeaway": "Điều kiện tĩnh đã có response thực tế để thử; bằng chứng tiến trình tự thoát nằm ngay ở bước cuối.",
        "narration": "Ở đây có một chi tiết dễ nhầm: nhận chữ o không làm chương trình thoát ngay. IDA cho thấy main luôn ngủ 30 giây sau beacon, rồi mới kiểm tra cờ. Ảnh tiếp theo là phép so sánh byte đầu với 111, tức chữ o. Burp xác nhận response thực tế có đúng một byte o."
      },
      {
        "id": "lab01-exit",
        "title": "Procmon xác nhận tiến trình tự kết thúc, không tự xóa tệp",
        "explanation": "Trong lượt bổ sung, Lab13-01.exe có PID 4992. Đối chiếu nhật ký ghi nhận TCP Receive lúc 20:36:59.0024594 và Process Exit lúc 20:37:29.0234778, cách nhau 30.0210184 giây. Hồ sơ phiên chạy xác nhận không cưỡng bức dừng tiến trình. Mã main dọn Winsock rồi return 0; không có bằng chứng xóa mẫu.",
        "evidence": [
          {
            "id": "EVID-37",
            "where": "Sự kiện Process Exit của Lab13-01.exe, PID 4992; Detail ghi Exit Status: 0 và thời điểm 20:37:29.0234778.",
            "conclusion": "Ảnh chứng minh Exit 0. Khoảng trễ 30.021 giây và việc không bị kill được đối chiếu thêm với CSV và hồ sơ phiên chạy, không suy ra chỉ từ một dòng Exit."
          }
        ],
        "takeaway": "Lab13-01: domain XOR, hostname Base64, beacon HTTP, response o dẫn tới tự thoát sau lần ngủ cuối. Tự thoát không đồng nghĩa tự hủy hay xóa tệp.",
        "narration": "Cuối cùng, Procmon ghi nhận PID 4992 kết thúc với Exit Status bằng 0. Đối chiếu mốc nhận dữ liệu với mốc thoát cho khoảng 30,021 giây, phù hợp lần ngủ cuối trong mã máy. Phiên này không bị kill. Kết luận là tự kết thúc tiến trình, không gọi là tự xóa hay tự hủy."
      }
    ],
    "lab13-02": [
      {
        "id": "lab02-capture",
        "title": "Mẫu thứ hai thu thập ảnh desktop bằng GDI",
        "explanation": "Lab13-02.exe là mẫu gián điệp màn hình. Hàm sub_401070 lấy kích thước desktop, tạo vùng bitmap tương thích, dùng BitBlt sao chép hình ảnh và tạo dữ liệu BMP 32 bit mỗi pixel. Điều này giải thích vì sao đầu ra giải mã là ảnh desktop, không phải tài liệu hay văn bản.",
        "evidence": [
          {
            "id": "EVID-10",
            "where": "Mã giả sub_401070: GetSystemMetrics, GetDesktopWindow, GetDC, CreateCompatibleDC, BitBlt và biBitCount = 32.",
            "conclusion": "Tổ hợp API và cấu trúc bitmap thể hiện chức năng chụp màn hình. Kết quả chạy và ảnh được khôi phục sẽ được đối chiếu ở các bước sau."
          }
        ],
        "takeaway": "Dữ liệu đầu vào của lớp mã hóa là bitmap desktop.",
        "narration": "Lab13-02 có mục tiêu khác: chụp màn hình desktop. Ảnh IDA cho thấy các API GDI, đặc biệt là BitBlt, cùng cấu hình bitmap 32 bit mỗi pixel. Đây là căn cứ tĩnh cho chức năng chụp ảnh; những phần sau sẽ đối chiếu với tệp thật mà mẫu tạo ra."
      },
      {
        "id": "lab02-rabbit",
        "title": "Ảnh được che giấu bằng biến thể Rabbit với trạng thái ban đầu bằng 0",
        "explanation": "Trước khi mã hóa, chương trình đặt toàn bộ 68 byte trạng thái về 0. Cấu trúc cập nhật counter và bộ hằng số nhận diện một biến thể của Rabbit stream cipher. Trên đường gọi được phân tích không có bước thiết lập khóa hay warmup như triển khai Rabbit chuẩn. Không thể chỉ dùng một phép XOR khóa một byte để khôi phục tệp này.",
        "evidence": [
          {
            "id": "EVID-34",
            "where": "Hàm sub_40181F: memset vùng ngữ cảnh về 0, độ dài 0x44, tương đương 68 byte, rồi gọi hàm xử lý dữ liệu.",
            "conclusion": "Trạng thái được khởi tạo lại bằng 0 trên đường gọi này. Tính chất đó được dùng khi tái lập keystream để giải mã."
          },
          {
            "id": "EVID-12",
            "where": "Hàm sub_4012DD: các giá trị counter ở dạng thập phân 1295307613, -749914925 và 886263092.",
            "conclusion": "Các giá trị tương ứng 0x4D34D35D, 0xD34D34D3 và 0x34D34D34. Hằng số đầu khác Rabbit chuẩn; ảnh hiển thị decimal, không phải ảnh đã chuyển sang hex."
          }
        ],
        "takeaway": "Cần tái lập đúng biến thể và trạng thái của mẫu; dùng bộ giải mã Rabbit chuẩn nguyên trạng có thể cho kết quả sai.",
        "narration": "Dữ liệu ảnh không được lưu rõ mà đi qua một biến thể Rabbit. Ảnh đầu cho thấy 68 byte trạng thái bị đặt về 0. Ảnh sau là các hằng số cập nhật counter, đang hiển thị ở hệ thập phân. Đối chiếu cấu trúc và hằng số cho thấy đây là biến thể, nên khi giải mã phải bám đúng triển khai trong mẫu."
      },
      {
        "id": "lab02-write",
        "title": "Mẫu ghi tệp temp ngay tại thư mục làm việc",
        "explanation": "Hàm điều phối thực hiện chụp, mã hóa rồi ghi đĩa. Tên tệp có dạng temp%08x, lấy giá trị từ GetTickCount. Chữ temp chỉ là tiền tố tên; tệp nằm trong thư mục làm việc hiện tại, không mặc định là thư mục %TEMP% của Windows. Ba ảnh Procmon sau mã giả thuộc lượt đầu, PID 3556.",
        "evidence": [
          {
            "id": "EVID-11",
            "where": "Hàm sub_401851: lần lượt gọi hàm chụp, hàm mã hóa, GetTickCount, định dạng temp%08x và hàm ghi tệp.",
            "conclusion": "Mã máy nối ba chức năng thành một luồng: thu ảnh, mã hóa, lưu tệp có tên theo tick."
          },
          {
            "id": "EVID-07",
            "where": "Event Properties của Process Start: Command line C:\\Lab13Analysis\\samples\\Lab13-02.exe và Current directory C:\\Lab13Analysis\\runtime.",
            "conclusion": "Xác định CWD của lượt PID 3556. Dù tên tệp ảnh cũ có chữ writefile, nội dung ảnh này là Process Start, không phải thao tác ghi."
          },
          {
            "id": "EVID-06",
            "where": "Danh sách sự kiện của Lab13-02.exe PID 3556: Process Start, Thread Create và Load Image.",
            "conclusion": "Đã theo dõi tiến trình thực thi của đúng mẫu. Các sự kiện khởi động không tự chứng minh chức năng chụp; cần sự kiện ghi và tệp đầu ra bên dưới."
          },
          {
            "id": "EVID-08",
            "where": "Dòng WriteFile thành công: C:\\Lab13Analysis\\runtime\\temp002a9d1e, Length 5,436,114 bytes.",
            "conclusion": "Mẫu đã ghi tệp mã hóa tại CWD. Đây là tệp dùng cho cặp ảnh HxD và Paint ở bước khôi phục."
          }
        ],
        "takeaway": "temp002a9d1e là tệp do mẫu tạo, nằm ở CWD. Tên gọi temp không đủ để kết luận đường dẫn Windows Temp.",
        "narration": "Hàm điều phối chụp ảnh, mã hóa rồi tạo tên tệp từ GetTickCount. Trong Procmon, cửa sổ thuộc tính xác định thư mục làm việc là C:\\Lab13Analysis\\runtime. Dòng WriteFile bên dưới ghi nhận tệp temp002a9d1e với hơn 5,4 triệu byte. Vì vậy chữ temp ở đây là tên tệp, không phải bằng chứng mẫu ghi vào thư mục Temp của Windows."
      },
      {
        "id": "lab02-interval",
        "title": "Chu kỳ thực tế khoảng 10 giây, không phải 5 giây",
        "explanation": "Hàm main có hai Sleep(5000) trong mỗi vòng: một trước và một sau hàm chụp, mã hóa, ghi tệp. Hai lần ghi liên tiếp vì thế cách nhau ít nhất 10 giây cộng thời gian xử lý. Lượt kiểm chứng bổ sung dùng PID 3876; mỗi tệp có 5.461.422 byte, khác lượt đầu vì kích thước desktop đã thay đổi.",
        "evidence": [
          {
            "id": "EVID-33",
            "where": "Hàm main sub_4018D8: hai lời gọi Sleep(5000) nằm hai phía lời gọi sub_401851.",
            "conclusion": "Không đọc một lệnh Sleep rồi kết luận chu kỳ chụp là 5 giây; phải tính cả vòng lặp."
          },
          {
            "id": "EVID-38",
            "where": "Hai WriteFile cùng PID 3876 lúc 20:39:31.7045111 và 20:39:41.9263907; mỗi lần Length 5,461,422.",
            "conclusion": "Khoảng thực nghiệm là 10.2218796 giây, phù hợp hai lần Sleep cộng xử lý. Không gán toàn bộ phần chênh cho riêng BitBlt khi chưa có đo chi tiết."
          }
        ],
        "takeaway": "Kích thước tệp phụ thuộc desktop của từng lượt. Dữ liệu PID 3876 không được ghép thành cùng phiên với PID 3556.",
        "narration": "Chu kỳ là điểm cần đọc kỹ. Main có hai lần ngủ 5 giây chứ không phải một. Ảnh Procmon của lượt bổ sung ghi hai lần WriteFile cùng PID cách nhau khoảng 10,222 giây. Kích thước tệp ở lượt này lớn hơn lượt đầu do desktop khác kích thước, không phải hai kết quả mâu thuẫn."
      },
      {
        "id": "lab02-decode",
        "title": "HxD đối chiếu tệp mã hóa với cấu trúc BMP sau khôi phục",
        "explanation": "Quay lại đúng tệp temp002a9d1e của lượt đầu. Trước khôi phục, đầu tệp là E2 EE, không phải chữ ký BMP. Sau khi giải mã bằng keystream tương ứng biến thể Rabbit, tệp có magic 42 4D, tức BM, cùng các trường kích thước bitmap hợp lệ. Đây là đối chiếu tệp đầu ra, không phải ảnh một chương trình đang chạy lệnh giải mã trong terminal.",
        "evidence": [
          {
            "id": "EVID-19",
            "where": "HxD mở temp002a9d1e: offset 00000000 bắt đầu E2 EE 44 DE 21 CC.",
            "conclusion": "Tệp chưa có header BMP rõ. Hai byte E2 EE phù hợp phép XOR của BM với hai byte keystream đầu trong triển khai được tái lập."
          },
          {
            "id": "EVID-20",
            "where": "HxD mở recovered.bmp: magic 42 4D; header chứa kích thước tệp 5.436.114 byte, chiều rộng 1505, chiều cao 903, 32 bpp.",
            "conclusion": "Kết quả khôi phục có cấu trúc BMP hợp lệ, đúng kích thước tệp lượt đầu. Chưa có bản plaintext độc lập trước mã hóa để so byte-for-byte."
          }
        ],
        "takeaway": "Không chỉ đổi đuôi thành .bmp: dữ liệu sau khôi phục phải có header và cấu trúc ảnh nhất quán.",
        "narration": "Hai ảnh HxD sử dụng cùng tệp của lượt đầu. Trước giải mã, dữ liệu bắt đầu bằng E2 EE. Sau giải mã, đầu tệp trở thành BM và header mô tả bitmap 1505 nhân 903, 32 bit mỗi pixel. Đây là kiểm tra cấu trúc thực tế, không chỉ đổi tên hay đổi phần mở rộng."
      },
      {
        "id": "lab02-recovered",
        "title": "Paint mở được ảnh desktop đã khôi phục",
        "explanation": "Kiểm tra cuối cùng là mở recovered.bmp bằng Paint trong máy ảo. Ảnh hiển thị desktop cùng cửa sổ Procmon, phù hợp chức năng chụp màn hình tìm thấy trong IDA. Lượt bổ sung cũng thu được BMP hợp lệ 1507×906; không dùng kích thước đó để chú thích ảnh Paint của lượt đầu.",
        "evidence": [
          {
            "id": "EVID-21",
            "where": "Khung ảnh trong Microsoft Paint và thanh trạng thái hiển thị 1505 × 903 px.",
            "conclusion": "Tệp khôi phục được ứng dụng ảnh đọc và hiển thị thành desktop. Đây là bằng chứng thực nghiệm cho việc mẫu tạo dữ liệu ảnh, không chứng minh mẫu đã gửi ảnh qua mạng."
          }
        ],
        "takeaway": "Lab13-02: chụp desktop, mã hóa Rabbit biến thể, ghi tệp ở CWD khoảng mỗi 10 giây. Mẫu được dừng sau cửa sổ quan sát, không phải tự thoát.",
        "narration": "Paint mở được tệp khôi phục và hiển thị desktop có cửa sổ Procmon. Kết quả này nối lại với hàm BitBlt ở đầu phần phân tích. Có thể kết luận mẫu chụp và lưu ảnh màn hình đã mã hóa; không mở rộng thành khẳng định đã gửi ảnh qua mạng. Mẫu được dừng sau khi quan sát."
      }
    ],
    "lab13-03": [
      {
        "id": "lab03-connect",
        "title": "Mẫu thứ ba có kiến trúc reverse shell TCP",
        "explanation": "Reverse shell là cơ chế để chương trình trên máy đích chủ động kết nối về máy điều khiển, đưa lệnh vào shell rồi gửi kết quả ra. Mã máy của Lab13-03.exe chuẩn bị kết nối tới cổng TCP 8910 và dùng cmd.exe làm bộ xử lý lệnh. Cần tách thiết kế trong mã máy khỏi việc đã chứng minh lệnh chạy thành công.",
        "evidence": [
          {
            "id": "EVID-13",
            "where": "Hàm main: khởi tạo Winsock, WSASocketA, port 8910, connect và lời gọi khởi tạo ngữ cảnh khóa.",
            "conclusion": "Xác định cơ chế kết nối và khởi tạo trong mã. Khóa đầy đủ được đối chiếu là ijklmnopqrstuvwx; tên nhãn IDA rút gọn không phải toàn bộ nội dung khóa."
          }
        ],
        "takeaway": "Cổng 8910 là đích kết nối của mẫu. Có kết nối chưa đủ để kết luận đã điều khiển được cmd.exe.",
        "narration": "Lab13-03 có kiến trúc reverse shell. Mẫu chủ động kết nối về cổng 8910, dự kiến nhận lệnh và chuyển kết quả của cmd.exe về đầu điều khiển. Ảnh main cho thấy phần thiết lập này. Từ đầu cần phân biệt kiến trúc tìm thấy trong mã với phần đã chạy thành công trong thực nghiệm."
      },
      {
        "id": "lab03-pipes",
        "title": "Anonymous pipe nối dữ liệu mạng với đầu vào, đầu ra cmd.exe",
        "explanation": "Pipe là kênh truyền dữ liệu giữa các tiến trình. Mẫu tạo hai cặp anonymous pipe, chuẩn bị handle kế thừa rồi gán vào các luồng chuẩn của tiến trình con. Với STARTF_USESTDHANDLES, cmd.exe nhận đầu vào từ pipe và ghi đầu ra, lỗi vào pipe còn lại thay vì chỉ dùng cửa sổ console.",
        "evidence": [
          {
            "id": "EVID-14",
            "where": "Đầu sub_4015B7: các biến hReadPipe, hWritePipe, STARTUPINFOA và PROCESS_INFORMATION.",
            "conclusion": "Ảnh giới thiệu cấu trúc dữ liệu được dùng. Chỉ danh sách biến chưa chứng minh pipe đã được tạo hoặc cmd.exe đã chạy."
          },
          {
            "id": "EVID-26",
            "where": "Hai lời gọi CreatePipe và DuplicateHandle trong sub_4015B7.",
            "conclusion": "Mã máy thực sự tạo các kênh pipe và chuẩn bị handle. Đây là ảnh IDA, không phải ảnh socket hay listener mạng."
          },
          {
            "id": "EVID-27",
            "where": "StartupInfo.hStdInput, hStdOutput, hStdError; cờ STARTF_USESTDHANDLES và lời gọi CreateProcessA.",
            "conclusion": "Xác định cách chuyển hướng I/O khi tạo shell. Đây là thiết kế tĩnh; bằng chứng tiến trình con thực tế nằm ở bước 5."
          }
        ],
        "takeaway": "Hai chiều I/O được nối qua pipe. Tạo cmd.exe không tự chứng minh một lệnh nhận từ mạng đã được thực thi.",
        "narration": "Mẫu dùng hai cặp pipe để nối dữ liệu với cmd.exe. Ảnh đầu chỉ là khai báo biến. Ảnh tiếp theo mới cho thấy CreatePipe, còn ảnh cuối thể hiện gán các handle vào đầu vào, đầu ra, lỗi và gọi CreateProcessA. Ba ảnh có vai trò khác nhau, không dùng một ảnh khai báo để khẳng định toàn bộ luồng đã chạy."
      },
      {
        "id": "lab03-inbound",
        "title": "Chiều nhận lệnh dùng Custom Base64",
        "explanation": "Luồng inbound đọc dữ liệu từ socket, giải biểu diễn bằng bảng Base64 tùy biến rồi dự kiến ghi lệnh vào stdin pipe của cmd.exe. Bảng bắt đầu bằng C thay vì A: phần chữ hoa và chữ thường được xoay hai vị trí, chữ số cùng +/ giữ nguyên. Đây là encoding, không phải AES của chiều gửi.",
        "evidence": [
          {
            "id": "EVID-36",
            "where": "Vùng dữ liệu VA 0x004120A4: byte 43h tức C và alphabet CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/.",
            "conclusion": "Xác định bảng Custom Base64 của chiều nhận. Dùng bảng Base64 chuẩn mà không ánh xạ lại sẽ giải sai."
          },
          {
            "id": "EVID-16",
            "where": "Luồng StartAddress tại 0x0040147C: ReadFile từ socket, gọi sub_401082, WriteFile vào pipe.",
            "conclusion": "Mã máy nối bộ giải Custom Base64 với stdin pipe. Chưa có trace runtime xác nhận payload kiểm tra đã đi qua đủ các bước này."
          }
        ],
        "takeaway": "Chiều nhận lệnh: socket, giải Custom Base64, stdin pipe. Đây là kết luận phân tích tĩnh.",
        "narration": "Chiều nhận dùng Custom Base64, với bảng bắt đầu bằng chữ C. Ảnh bảng ký tự giải thích sự khác biệt; ảnh worker cho thấy đọc socket, giải dữ liệu rồi ghi vào pipe. Đây là luồng trong mã máy. Không vì nhìn thấy hàm decode mà khẳng định payload thử nghiệm đã được giải mã thành công."
      },
      {
        "id": "lab03-outbound",
        "title": "Chiều gửi kết quả dùng AES-128-CBC, không phải Custom Base64",
        "explanation": "Luồng outbound đọc dữ liệu đầu ra của shell, mã hóa bằng AES-128-CBC rồi ghi ra socket. Mã AES nằm trong chính mẫu, không dùng Windows CryptoAPI. Đối chiếu tĩnh xác định khóa 16 byte ijklmnopqrstuvwx, IV ban đầu 16 byte 0 và feedback CBC được duy trì giữa các lần gọi. Hai chiều dùng cơ chế khác nhau, không phải hai lớp luôn lồng nhau.",
        "evidence": [
          {
            "id": "EVID-35",
            "where": "Hàm sub_40352D: XOR plaintext với feedback, gọi lõi AES, rồi memcpy ciphertext vào ngữ cảnh +0x3F4.",
            "conclusion": "Cấu trúc xử lý thể hiện chế độ CBC; nhận diện AES còn được đối chiếu lõi và S-box trong hồ sơ tĩnh. Ảnh mã máy không chứng minh đã thu được ciphertext runtime."
          },
          {
            "id": "EVID-15",
            "where": "Worker sub_40132B: đọc stdout pipe, gọi sub_40352D với hướng mã hóa, sau đó ghi ra socket.",
            "conclusion": "Xác định đường gửi kết quả được mã hóa. Đây là mã giả IDA, không phải ảnh Process Hacker hay bằng chứng có đầu ra mạng thành công."
          }
        ],
        "takeaway": "Inbound là Custom Base64; outbound là AES-128-CBC cài trong mẫu. Khóa và IV ở đây là phát hiện tĩnh.",
        "narration": "Chiều gửi khác chiều nhận: đầu ra shell được mã hóa AES-128-CBC. Ảnh đầu cho thấy XOR với feedback, gọi lõi mã hóa rồi cập nhật feedback. Ảnh worker nối phần đó với stdout và socket. Khóa được đối chiếu là ijklmnopqrstuvwx, IV ban đầu bằng 0. Đây là AES cài trong mẫu, không phải CryptoAPI."
      },
      {
        "id": "lab03-child",
        "title": "Procmon xác nhận mẫu đã tạo cmd.exe",
        "explanation": "Trong lượt đầu, tiến trình Lab13-03.exe có PID 4336 và tạo cmd.exe PID 4532. Hai ảnh dưới là danh sách sự kiện và thuộc tính chi tiết của quan hệ cha–con trong cùng lượt này. Chúng chứng minh shell được tạo, chưa chứng minh shell đã xử lý một lệnh nhận từ mạng.",
        "evidence": [
          {
            "id": "EVID-18",
            "where": "Các dòng Process Create của Lab13-03.exe PID 4336, gồm cmd.exe và conhost.exe.",
            "conclusion": "Đã quan sát hành vi tạo tiến trình của mẫu, không chỉ thấy lời gọi CreateProcessA trong mã."
          },
          {
            "id": "EVID-22",
            "where": "Event Properties của Process Create cmd.exe PID 4532 và thông tin Parent PID 4336.",
            "conclusion": "Xác nhận cmd.exe thuộc quan hệ cha–con với mẫu trong phiên này. PID 1296 của lượt bổ sung là một phiên khác."
          }
        ],
        "takeaway": "Hành vi tạo shell đã được xác nhận động. Khả năng thực thi lệnh từ xa vẫn cần bằng chứng riêng.",
        "narration": "Về hành vi đã chạy, Procmon ghi nhận Lab13-03 tạo cmd.exe. Ảnh thuộc tính xác định tiến trình cha PID 4336 và tiến trình con PID 4532. Đây là bằng chứng động của việc tạo shell. Chưa thể từ quan hệ cha–con này suy ra lệnh từ mạng đã chạy."
      },
      {
        "id": "lab03-network",
        "title": "Process Hacker xác nhận kết nối TCP tới cổng 8910",
        "explanation": "Hai ảnh Process Hacker thuộc lượt chạy khác, PID 5188. Ảnh tiến trình cho thấy mẫu đang tồn tại; ảnh mạng ghi nhận TCP Established, local port 49774 tới cổng đích 8910. Không ghép PID này với cmd.exe PID 4532 của hai ảnh Procmon trước thành cùng một cây tiến trình.",
        "evidence": [
          {
            "id": "EVID-24",
            "where": "Danh sách tiến trình Process Hacker: dòng Lab13-03.exe PID 5188.",
            "conclusion": "Ảnh xác nhận mẫu đang chạy ở PID 5188. Snapshot này không hiển thị tiến trình con bên dưới, nên không dùng nó để chứng minh cây cmd.exe."
          },
          {
            "id": "EVID-25",
            "where": "Thông tin mạng của Lab13-03.exe PID 5188: TCP Established, local port 49774, remote port 8910.",
            "conclusion": "Đã thiết lập kết nối trong môi trường cục bộ. Established là trạng thái TCP, không chứng minh đã giải mã, thực thi lệnh hay gửi kết quả mã hóa."
          }
        ],
        "takeaway": "Đã quan sát cả tạo cmd.exe và kết nối TCP qua các lượt được ghi rõ. Không biến hai quan sát đó thành khẳng định reverse shell hoàn tất end-to-end.",
        "narration": "Process Hacker ghi nhận kết nối TCP Established tới cổng 8910. Hai ảnh này thuộc lượt PID 5188, khác lượt Procmon vừa xem. Trạng thái Established chỉ xác nhận kết nối TCP. Nó không tự chứng minh lệnh đã được decode, đã chạy trong cmd.exe hay đã có dữ liệu AES gửi về."
      },
      {
        "id": "lab03-limit",
        "title": "Phần chưa chứng minh: lệnh kiểm tra và phản hồi AES runtime",
        "explanation": "Lượt bổ sung ghi nhận mẫu PID 5672 tạo cmd.exe PID 1296 và nhận 28 byte qua TCP. Chuỗi thử được đối chiếu ngoại tuyến thành echo LAB13_VERIFIED\\r\\n, dài 21 byte. Tuy nhiên observer thu được 0 byte phản hồi. Chưa có API trace chứng minh mẫu đã giải biểu diễn, ghi vào stdin, chạy echo hoặc thực hiện đường AES outbound. Nguyên nhân thiếu đầu ra chưa xác định.",
        "evidence": [],
        "record": "Đối chiếu từ Procmon CSV, hồ sơ phiên chạy và tệp thu phản hồi; không có ảnh GUI mới cho lượt này. Nội dung log được trình bày thành văn bản trong SPA, không giả làm ảnh chụp công cụ.",
        "metrics": [
          ["Đã ghi nhận", "TCP Receive 28 byte; cmd.exe PID 1296"],
          ["Phản hồi thu được", "0 byte"],
          ["Chưa xác nhận", "Decode, stdin pipe, echo, AES outbound"],
          ["Nguyên nhân", "Chưa xác định"]
        ],
        "takeaway": "Lab13-03: kiến trúc reverse shell và hai cơ chế dữ liệu đã được giải thích tĩnh; thực nghiệm mới xác nhận một phần. Không kết luận chạy lệnh từ xa thành công.",
        "narration": "Lượt bổ sung nhận được 28 byte payload thử nghiệm, nhưng phía thu không có byte phản hồi nào. Vì vậy em chưa kết luận lệnh echo đã chạy hay đường AES outbound đã hoàn tất. Nguyên nhân chưa được xác định. Kết quả mẫu ba là xác nhận được kiến trúc và một phần hành vi, không phải kiểm chứng end-to-end thành công."
      }
    ]
  }
};
