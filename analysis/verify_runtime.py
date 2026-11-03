#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bộ kiểm định độc lập dữ liệu thực nghiệm runtime Lab13.
Tái lập và xác minh chặt chẽ telemetry, Procmon CSV, hash SHA256 và row indexes.
"""

import base64
import csv
import hashlib
import json
import os
import struct
import sys
from datetime import datetime
from pathlib import Path


def parse_procmon_time(ts_str: str) -> float:
    time_part, ampm = ts_str.strip().rsplit(" ", 1)
    h, m, sec_frac = time_part.split(":")
    s, frac = sec_frac.split(".")
    h = int(h)
    if ampm.upper() == "PM" and h != 12:
        h += 12
    elif ampm.upper() == "AM" and h == 12:
        h = 0
    return h * 3600 + int(m) * 60 + int(s) + int(frac) / (10 ** len(frac))


def compute_sha256(filepath: Path) -> str:
    return hashlib.sha256(filepath.read_bytes()).hexdigest()


def run_verification(write_report=False):
    base_dir = Path(__file__).resolve().parent.parent
    verif_dir = base_dir / "artifacts" / "verification"
    analysis_dir = base_dir / "analysis"

    assert verif_dir.exists(), f"Missing verification directory: {verif_dir}"

    csv_path = verif_dir / "verify-runtime.csv"
    assert csv_path.exists(), f"Missing runtime CSV: {csv_path}"

    # 0. SHA256 trace của tất cả artifacts
    sha256_trace = {}
    for item in sorted(verif_dir.iterdir()):
        if item.is_file():
            sha256_trace[item.name] = compute_sha256(item)

    assert sha256_trace["verify-runtime.csv"] == "29ce7926cdf57d692b1cf39d130157ff173c97219b2fdd521cb10169bf0880ac"

    # 1. Trích xuất và định vị chính xác dòng Procmon CSV
    lab01_events = []
    lab02_writes = []
    lab03_events = []

    csv_row_matches = {
        "lab01_tcp_receive": None,
        "lab01_process_exit": None,
        "lab02_write_1": None,
        "lab02_write_2": None,
        "lab03_child_cmd_create": None,
        "lab03_tcp_receive_28b": None,
    }

    with open(csv_path, "r", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, start=2):
            proc = row.get("Process Name", "")
            op = row.get("Operation", "")
            pid = row.get("PID", "")
            path = row.get("Path", "")
            detail = row.get("Detail", "")

            if proc == "Lab13-01.exe" and pid == "4992":
                if op == "TCP Receive" and "Length: 137" in detail:
                    csv_row_matches["lab01_tcp_receive"] = row_idx
                    lab01_events.append((row_idx, row))
                elif op == "Process Exit":
                    csv_row_matches["lab01_process_exit"] = row_idx
                    lab01_events.append((row_idx, row))
                elif op == "Process Start":
                    lab01_events.append((row_idx, row))
            elif proc == "Lab13-02.exe" and pid == "3876":
                if op == "WriteFile" and "temp00ca77b9" in path:
                    csv_row_matches["lab02_write_1"] = row_idx
                    lab02_writes.append((row_idx, row))
                elif op == "WriteFile" and "temp00ca9fb4" in path:
                    csv_row_matches["lab02_write_2"] = row_idx
                    lab02_writes.append((row_idx, row))
            elif proc == "Lab13-03.exe" and pid == "5672":
                if op == "Process Create" and "cmd.exe" in detail and "PID: 1296" in detail:
                    csv_row_matches["lab03_child_cmd_create"] = row_idx
                    lab03_events.append((row_idx, row))
                elif op == "TCP Receive" and "Length: 28" in detail:
                    csv_row_matches["lab03_tcp_receive_28b"] = row_idx
                    lab03_events.append((row_idx, row))
                elif op in ("TCP Connect", "TCP Disconnect"):
                    lab03_events.append((row_idx, row))

    # ----------------------------------------------------
    # Lab13-01 Verification
    # Domain resource dùng XOR0x3B; hostname12byte dùng Base64 chuẩn, không XOR.
    # Sleep30000 vô điều kiện sau beacon; cờ'o' khiến main WSACleanup/return0.
    # ----------------------------------------------------
    lab01_exit_json = json.loads((verif_dir / "lab01-exit.json").read_text(encoding="utf-8-sig"))
    assert lab01_exit_json["sample"] == "Lab13-01.exe"
    assert lab01_exit_json["pid"] == 4992
    assert lab01_exit_json["exitCode"] == 0
    assert lab01_exit_json["forced"] is False

    http_o_path = verif_dir / "http-o.jsonl"
    assert http_o_path.exists()
    http_o = json.loads(http_o_path.read_text(encoding="utf-8-sig").strip().splitlines()[0])
    assert http_o["response_hex"] == "6f", "Expected byte 'o' (0x6f) response"
    assert http_o["path"] in ("/REVTS1RPUC1WNVZD/", "/REVTS1RPUC1WNVZD")

    lab01_recv = [e for idx, e in lab01_events if e["Operation"] == "TCP Receive"]
    lab01_exit = [e for idx, e in lab01_events if e["Operation"] == "Process Exit"]
    assert len(lab01_recv) == 1, "Missing Lab13-01 TCP Receive in Procmon"
    assert len(lab01_exit) == 1, "Missing Lab13-01 Process Exit in Procmon"
    assert csv_row_matches["lab01_tcp_receive"] == 2647
    assert csv_row_matches["lab01_process_exit"] == 2718

    t_recv = parse_procmon_time(lab01_recv[0]["Time of Day"])
    t_exit = parse_procmon_time(lab01_exit[0]["Time of Day"])
    delta_lab01 = t_exit - t_recv
    assert abs(delta_lab01 - 30.0210184) < 1e-6, f"Lab13-01 delta mismatch: {delta_lab01} != 30.0210184"

    # ----------------------------------------------------
    # Lab13-02 Verification
    # Mã độc dùng Rabbit-derived stream cipher (hằng số 0x4D34D35D, state 68B), KHÔNG phải simple XOR.
    # Ghi tệp tempXXXX ngay CWD (C:\Lab13Analysis\verify\captures\), KHÔNG phải thư mục Temp (%TEMP%).
    # 2 lần Sleep(5000) liên tiếp tạo khoảng nghỉ >=10s. Chênh lệch ~0.222s là overhead tổng hợp
    # (GDI BitBlt + Rabbit cipher + file write + OS scheduling), không thể quy kết duy nhất cho GDI.
    # Khẳng định tệp temp00ca77b9.enc và recovered-verify.bmp đạt đúng 5,461,422B (1507x906 32bpp).
    # ----------------------------------------------------
    lab02_files = json.loads((verif_dir / "lab02-files2.json").read_text(encoding="utf-8-sig"))
    assert len(lab02_files) == 3
    for f_meta in lab02_files:
        assert f_meta["Length"] == 5461422, f"Expected 5461422 bytes, got {f_meta['Length']}"

    assert len(lab02_writes) == 2, f"Expected exactly 2 target write events, got {len(lab02_writes)}"
    assert csv_row_matches["lab02_write_1"] == 3271
    assert csv_row_matches["lab02_write_2"] == 3274

    w1_time_str = lab02_writes[0][1]["Time of Day"]
    w2_time_str = lab02_writes[1][1]["Time of Day"]
    t_w1 = parse_procmon_time(w1_time_str)
    t_w2 = parse_procmon_time(w2_time_str)
    delta_lab02 = t_w2 - t_w1
    assert abs(delta_lab02 - 10.2218796) < 1e-6, f"Lab13-02 delta mismatch: {delta_lab02} != 10.2218796"
    assert lab02_writes[0][1]["Path"] == r"C:\Lab13Analysis\verify\captures\temp00ca77b9"
    assert lab02_writes[1][1]["Path"] == r"C:\Lab13Analysis\verify\captures\temp00ca9fb4"

    enc_path = verif_dir / "temp00ca77b9.enc"
    bmp_path = verif_dir / "recovered-verify.bmp"
    assert enc_path.exists(), "Missing temp00ca77b9.enc"
    assert bmp_path.exists(), "Missing recovered-verify.bmp"
    assert enc_path.stat().st_size == 5461422
    assert bmp_path.stat().st_size == 5461422

    bmp_bytes = bmp_path.read_bytes()
    assert bmp_bytes[:2] == b"BM"
    b_width = struct.unpack("<i", bmp_bytes[18:22])[0]
    b_height = struct.unpack("<i", bmp_bytes[22:26])[0]
    b_bpp = struct.unpack("<H", bmp_bytes[28:30])[0]
    assert b_width == 1507 and b_height == 906 and b_bpp == 32, f"BMP mismatch: {b_width}x{b_height} {b_bpp}bpp"
    sys.path.insert(0, str(base_dir / "artifacts"))
    from decrypt_rabbit import RabbitLab1302
    assert RabbitLab1302().process(enc_path.read_bytes()) == bmp_bytes
    for _, event in lab02_writes:
        assert "Length: 5,461,422" in event["Detail"]

    # ----------------------------------------------------
    # Lab13-03 Verification
    # Tĩnh: inbound Custom Base64; outbound AES-128-CBC cài trong mẫu.
    # KHÔNG phải shellcode, KHÔNG phải Substituted XOR.
    # 28 bytes nhận qua mạng ('BYPqdaDOSWKzO19YTXLLTmnHTC0M') chỉ là network payload nhận trên socket.
    # KHÔNG có bằng chứng runtime độc lập cho thấy malware đã giải mã hay cmd.exe đã thực thi lệnh.
    # Tệp phản hồi lab03-verify-cipher.bin kích thước 0 byte -> FAILED echo test (echo test thất bại, không phải PASS).
    # Nguyên nhân 0B: UNKNOWN (chưa chứng minh được giả thuyết 4096-byte pipe buffer).
    # ----------------------------------------------------
    lab03_run = json.loads((verif_dir / "lab03-run.json").read_text(encoding="utf-8-sig"))
    assert lab03_run["pid"] == 5672

    proc_names = {p["ProcessId"]: p["Name"] for p in lab03_run["processes"]}
    assert proc_names.get(5672) == "Lab13-03.exe"
    assert proc_names.get(5608) == "conhost.exe"
    assert proc_names.get(1296) == "cmd.exe"

    conn_8910 = [c for c in lab03_run["connections"] if c["RemotePort"] == 8910 and c["OwningProcess"] == 5672]
    assert len(conn_8910) >= 1, "Missing port 8910 connection from Lab13-03"

    # Assert trực tiếp các sự kiện trong lab03_events từ Procmon CSV
    child_cmd_events = [e for idx, e in lab03_events if e["Operation"] == "Process Create" and "cmd.exe" in e.get("Detail", "")]
    assert len(child_cmd_events) == 1, "Expected exactly 1 cmd.exe child creation in Procmon"
    assert csv_row_matches["lab03_child_cmd_create"] == 4237
    assert "PID: 1296" in child_cmd_events[0]["Detail"]

    tcp_recv_28b = [e for idx, e in lab03_events if e["Operation"] == "TCP Receive" and "Length: 28" in e.get("Detail", "")]
    assert len(tcp_recv_28b) == 1, "Expected exactly 1 TCP Receive with Length: 28 in Procmon"
    assert csv_row_matches["lab03_tcp_receive_28b"] == 4650
    tcp_log = [
        json.loads(line)
        for line in (verif_dir / "tcp8910.jsonl").read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]
    sent = [item for item in tcp_log if item.get("event") == "sent_fixed_echo"]
    assert len(sent) == 1
    wire = sent[0]["wire_ascii"].encode("ascii")
    assert wire == b"BYPqdaDOSWKzO19YTXLLTmnHTC0M"
    standard = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    custom = b"CDEFGHIJKLMNOPQRSTUVWXYZABcdefghijklmnopqrstuvwxyzab0123456789+/"
    plaintext = base64.b64decode(wire.translate(bytes.maketrans(custom, standard)), validate=True)
    assert plaintext == b"echo LAB13_VERIFIED\r\n" and len(plaintext) == 21
    assert base64.b64decode(b"REVTS1RPUC1WNVZD", validate=True) == b"DESKTOP-V5VC"

    cipher_bin = verif_dir / "lab03-verify-cipher.bin"
    assert cipher_bin.exists()
    assert len(cipher_bin.read_bytes()) == 0, "lab03-verify-cipher.bin must be 0 bytes (failed echo test)"

    # ----------------------------------------------------
    # Xuất runtime-verification.json
    # ----------------------------------------------------
    result_data = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "overall_runtime_status": "partial_runtime_coverage",
        "assertions_passed": True,
        "sha256_trace": sha256_trace,
        "csv_row_indexes": csv_row_matches,
        "samples": {
            "Lab13-01.exe": {
                "pid": 4992,
                "exit_status": 0,
                "csv_tcp_receive_row": csv_row_matches["lab01_tcp_receive"],
                "csv_process_exit_row": csv_row_matches["lab01_process_exit"],
                "tcp_receive_time": lab01_recv[0]["Time of Day"],
                "process_exit_time": lab01_exit[0]["Time of Day"],
                "sleep_interval_seconds": 30.0210184,
                "server_response_hex": "6f",
                "request_path": "/REVTS1RPUC1WNVZD/",
                "encoding_scheme": "Resource domain: XOR0x3B; separate hostname12byte: standard Base64, no hostname XOR",
                "exit_mechanism": "Sleep(30000) unconditional wait in main; invokes WSACleanup() and returns 0 (no direct ExitProcess call in main)",
                "verification_status": "VERIFIED_PASS"
            },
            "Lab13-02.exe": {
                "pid": 3876,
                "csv_write_rows": [
                    csv_row_matches["lab02_write_1"],
                    csv_row_matches["lab02_write_2"]
                ],
                "written_files": [
                    {"file": "temp00ca77b9", "row": 3271, "time": w1_time_str, "bytes": 5461422},
                    {"file": "temp00ca9fb4", "row": 3274, "time": w2_time_str, "bytes": 5461422}
                ],
                "target_directory": r"C:\Lab13Analysis\verify\captures (CWD, NOT %TEMP%)",
                "write_interval_seconds": 10.2218796,
                "cipher_algorithm": "Rabbit-derived stream cipher (constant 0x4D34D35D, 68-byte state), NOT simple XOR",
                "cycle_mechanism": "Two consecutive Sleep(5000) calls (pre-capture and post-capture) resulting in >=10s interval",
                "overhead_note": "Delta ~0.222s represents aggregate overhead (GDI BitBlt capture, Rabbit encryption, file I/O, OS scheduling); overhead not solely GDI provable",
                "recovered_bmp_dimensions": "1507x906 32bpp (5,461,422 bytes)",
                "verification_status": "VERIFIED_PASS"
            },
            "Lab13-03.exe": {
                "pid": 5672,
                "child_processes": [
                    {"name": "conhost.exe", "pid": 5608},
                    {"name": "cmd.exe", "pid": 1296, "csv_create_row": csv_row_matches["lab03_child_cmd_create"]}
                ],
                "c2_connection": {
                    "local_port": 49777,
                    "remote_port": 8910,
                    "state": "Established"
                },
                "cryptography_architecture": {
                    "inbound": "Custom Base64 with custom alphabet mapping (NOT shellcode, NOT Substituted XOR)",
                    "outbound": "AES-128-CBC implemented in sample functions; static identification only"
                },
                "inbound_network_payload": {
                    "csv_receive_row": csv_row_matches["lab03_tcp_receive_28b"],
                    "wire_ascii": "BYPqdaDOSWKzO19YTXLLTmnHTC0M",
                    "wire_length": 28,
                    "offline_plaintext": plaintext.decode("ascii"),
                    "offline_plaintext_bytes": 21,
                    "status": "RECEIVED_AS_NETWORK_PAYLOAD_ONLY",
                    "note": "No independent runtime evidence of payload decoding or cmd.exe execution"
                },
                "outbound_echo_verification": {
                    "captured_length_bytes": 0,
                    "test_status": "FAILED_ECHO_TEST",
                    "failure_cause": "UNKNOWN (pipe buffering / flush timing hypothesized; 4096-byte buffering unproven at runtime)",
                    "impact": "Socket connection and child creation observed; architecture inferred statically; no command execution or outbound AES runtime proof"
                },
                "verification_status": "PARTIAL_COVERAGE"
            }
        },
        "assert_checks": {
            "source_csv_sha256_matches": True,
            "lab01_natural_exit_status0_delay30s": True,
            "lab02_two_cwd_writes_delta10_2218796s": True,
            "lab02_recovered_bmp_header1507x906_32bpp": True,
            "lab03_cmd_child_pid1296_and_tcp_receive28b": True,
            "lab03_capture_is_empty_not_success": True
        },
        "check_scope": "Artifact assertions only; static algorithm descriptions are not runtime execution assertions."
    }

    if write_report:
        out_json = analysis_dir / "runtime-verification.json"
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        print(f"Report: {out_json}")
    print("[PASS] Artifact assertions; runtime coverage remains partial (Lab13-03 echo unverified).")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    run_verification(parser.parse_args().write_report)
