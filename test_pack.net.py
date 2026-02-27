import backend


# TEST 1 — Does TCP protocol number return "TCP"?

def test_tcp():
    result = backend.get_protocol_name(6)
    assert result == "TCP", f"Expected TCP but got {result}"
    print("PASS - test_tcp")


# TEST 2 — Does UDP protocol number return "UDP"?

def test_udp():
    result = backend.get_protocol_name(17)
    assert result == "UDP", f"Expected UDP but got {result}"
    print("PASS - test_udp")


# TEST 3 — Does ICMP protocol number return "ICMP"?

def test_icmp():
    result = backend.get_protocol_name(1)
    assert result == "ICMP", f"Expected ICMP but got {result}"
    print("PASS - test_icmp")


# TEST 4 — Does an unknown protocol number return "OTHER"?

def test_unknown_protocol():
    result = backend.get_protocol_name(99)
    assert result == "OTHER", f"Expected OTHER but got {result}"
    print("PASS - test_unknown_protocol")


# TEST 5 — Does storing one packet add it to the lists?

def test_store_one_packet():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "192.168.1.1", "8.8.8.8",
                         "TCP", "443", "52000", 60, b"data")
    assert len(backend.g_src_ips) == 1, "Expected 1 packet in list"
    print("PASS - test_store_one_packet")


# TEST 6 — Are the stored values saved correctly?

def test_store_packet_values_correct():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "192.168.1.1", "8.8.8.8",
                         "TCP", "443", "52000", 60, b"data")
    assert backend.g_src_ips[0]   == "192.168.1.1", "Wrong source IP"
    assert backend.g_dst_ips[0]   == "8.8.8.8",     "Wrong destination IP"
    assert backend.g_protocols[0] == "TCP",          "Wrong protocol"
    assert backend.g_sizes[0]     == 60,             "Wrong size"
    print("PASS - test_store_packet_values_correct")


# TEST 7 — Do all 8 lists stay the same length after storing?

def test_all_lists_same_length():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "1.1.1.1", "2.2.2.2", "TCP", "80", "443", 100, b"a")
    backend.store_packet("12:00:01.000", "3.3.3.3", "4.4.4.4", "UDP", "53", "500", 50,  b"b")
    assert len(backend.g_src_ips)   == 2, "g_src_ips wrong length"
    assert len(backend.g_protocols) == 2, "g_protocols wrong length"
    assert len(backend.g_raw_bytes) == 2, "g_raw_bytes wrong length"
    print("PASS - test_all_lists_same_length")


# TEST 8 — Does index 0 belong to first packet, index 1 to second?

def test_packet_index_in_sync():
    backend.clear_data()
    backend.store_packet("10:00:00.000", "10.0.0.1", "10.0.0.2", "TCP", "80", "60000", 100, b"first")
    backend.store_packet("10:00:01.000", "10.0.0.3", "10.0.0.4", "UDP", "53", "61000", 50,  b"second")
    assert backend.g_src_ips[0]   == "10.0.0.1", "First packet source IP wrong"
    assert backend.g_src_ips[1]   == "10.0.0.3", "Second packet source IP wrong"
    assert backend.g_protocols[1] == "UDP",       "Second packet protocol wrong"
    print("PASS - test_packet_index_in_sync")


# TEST 9 — Does clear_data empty all the lists?

def test_clear_empties_lists():
    backend.store_packet("12:00:00.000", "1.1.1.1", "2.2.2.2", "TCP", "80", "443", 100, b"x")
    backend.clear_data()
    assert len(backend.g_timestamps) == 0, "g_timestamps not cleared"
    assert len(backend.g_src_ips)    == 0, "g_src_ips not cleared"
    assert len(backend.g_dst_ips)    == 0, "g_dst_ips not cleared"
    assert len(backend.g_protocols)  == 0, "g_protocols not cleared"
    assert len(backend.g_sizes)      == 0, "g_sizes not cleared"
    assert len(backend.g_raw_bytes)  == 0, "g_raw_bytes not cleared"
    print("PASS - test_clear_empties_lists")


# TEST 10 — Does clear_data reset all the counters to zero?

def test_clear_resets_counters():
    backend.g_total = 5
    backend.g_tcp   = 3
    backend.g_udp   = 2
    backend.clear_data()
    assert backend.g_total == 0, "g_total not reset"
    assert backend.g_tcp   == 0, "g_tcp not reset"
    assert backend.g_udp   == 0, "g_udp not reset"
    assert backend.g_icmp  == 0, "g_icmp not reset"
    assert backend.g_other == 0, "g_other not reset"
    print("PASS - test_clear_resets_counters")


# TEST 11 — Does hex dump return empty list for empty bytes?

def test_hex_dump_empty():
    result = backend.format_hex_dump(b"")
    assert result == [], f"Expected empty list but got {result}"
    print("PASS - test_hex_dump_empty")

# TEST 12 — Does the first row offset start at 0000?

def test_hex_dump_offset_starts_at_zero():
    result = backend.format_hex_dump(b"Hello")
    assert result[0][0] == "0000", f"Expected 0000 but got {result[0][0]}"
    print("PASS - test_hex_dump_offset_starts_at_zero")


# TEST 13 — Does the second row offset show 0010 (16 in hex)?

def test_hex_dump_second_row_offset():
    result = backend.format_hex_dump(b"A" * 20)
    assert result[1][0] == "0010", f"Expected 0010 but got {result[1][0]}"
    print("PASS - test_hex_dump_second_row_offset")


# TEST 14 — Are printable characters shown as themselves?

def test_hex_dump_printable_chars():
    result = backend.format_hex_dump(b"ABC")
    assert result[0][2] == "ABC", f"Expected ABC but got {result[0][2]}"
    print("PASS - test_hex_dump_printable_chars")

# TEST 15 — Are non-printable bytes shown as dots?

def test_hex_dump_non_printable_as_dot():
    result = backend.format_hex_dump(b"\x00\x01\x02")
    assert result[0][2] == "...", f"Expected ... but got {result[0][2]}"
    print("PASS - test_hex_dump_non_printable_as_dot")


# TEST 16 — Does 16 bytes produce exactly 1 row?

def test_hex_dump_16_bytes_one_row():
    result = backend.format_hex_dump(b"A" * 16)
    assert len(result) == 1, f"Expected 1 row but got {len(result)}"
    print("PASS - test_hex_dump_16_bytes_one_row")


# TEST 17 — Does 17 bytes produce exactly 2 rows?

def test_hex_dump_17_bytes_two_rows():
    result = backend.format_hex_dump(b"A" * 17)
    assert len(result) == 2, f"Expected 2 rows but got {len(result)}"
    print("PASS - test_hex_dump_17_bytes_two_rows")


# RUN ALL TESTS

if __name__ == "__main__":

    tests = [
        test_tcp,
        test_udp,
        test_icmp,
        test_unknown_protocol,
        test_store_one_packet,
        test_store_packet_values_correct,
        test_all_lists_same_length,
        test_packet_index_in_sync,
        test_clear_empties_lists,
        test_clear_resets_counters,
        test_hex_dump_empty,
        test_hex_dump_offset_starts_at_zero,
        test_hex_dump_second_row_offset,
        test_hex_dump_printable_chars,
        test_hex_dump_non_printable_as_dot,
        test_hex_dump_16_bytes_one_row,
        test_hex_dump_17_bytes_two_rows,
    ]

    passed = 0
    failed = 0

    print("\n========== PACK-NET UNIT TESTS ==========\n")

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL  - {test.__name__} — {e}")
            failed += 1

    print(f"\n=========================================")
    print(f"  {passed} passed  |  {failed} failed  |  {len(tests)} total")
    print(f"=========================================\n")