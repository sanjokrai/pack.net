import unittest
from unittest.mock import MagicMock, patch
import backend


# TESTS FOR FUNCTION 1 — get_protocol_name


def test_tcp():
    assert backend.get_protocol_name(6) == "TCP"

def test_udp():
    assert backend.get_protocol_name(17) == "UDP"

def test_icmp():
    assert backend.get_protocol_name(1) == "ICMP"

def test_unknown_protocol():
    assert backend.get_protocol_name(99) == "OTHER"


# TESTS FOR FUNCTION 3 — store_packet


def test_store_packet_adds_to_lists():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "192.168.1.1", "8.8.8.8",
                         "TCP", "443", "52000", 60, b"data")
    assert len(backend.g_src_ips) == 1

def test_store_packet_correct_values():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "192.168.1.1", "8.8.8.8",
                         "TCP", "443", "52000", 60, b"data")
    assert backend.g_src_ips[0]   == "192.168.1.1"
    assert backend.g_dst_ips[0]   == "8.8.8.8"
    assert backend.g_protocols[0] == "TCP"
    assert backend.g_sizes[0]     == 60

def test_store_multiple_packets_lists_same_length():
    backend.clear_data()
    backend.store_packet("12:00:00.000", "1.1.1.1", "2.2.2.2", "TCP", "80", "443", 100, b"a")
    backend.store_packet("12:00:01.000", "3.3.3.3", "4.4.4.4", "UDP", "53", "500", 50,  b"b")
    assert len(backend.g_src_ips) == len(backend.g_protocols) == len(backend.g_raw_bytes) == 2

def test_store_packet_index_in_sync():
    backend.clear_data()
    backend.store_packet("10:00:00.000", "10.0.0.1", "10.0.0.2", "TCP", "80", "60000", 100, b"pkt1")
    backend.store_packet("10:00:01.000", "10.0.0.3", "10.0.0.4", "UDP", "53", "61000", 50,  b"pkt2")
    assert backend.g_src_ips[1]   == "10.0.0.3"
    assert backend.g_protocols[1] == "UDP"
    assert backend.g_raw_bytes[1] == b"pkt2"



# TESTS FOR FUNCTION 4 — format_hex_dump


def test_hex_dump_empty_bytes():
    assert backend.format_hex_dump(b"") == []

def test_hex_dump_returns_one_row():
    result = backend.format_hex_dump(b"Hello")
    assert len(result) == 1

def test_hex_dump_offset_starts_at_zero():
    result = backend.format_hex_dump(b"Hello")
    assert result[0][0] == "0000"

def test_hex_dump_second_row_offset_is_16():
    result = backend.format_hex_dump(b"A" * 20)
    assert result[1][0] == "0010"

def test_hex_dump_printable_chars_shown():
    result = backend.format_hex_dump(b"ABC")
    assert result[0][2] == "ABC"

def test_hex_dump_non_printable_shown_as_dot():
    result = backend.format_hex_dump(b"\x00\x01\x02")
    assert result[0][2] == "..."

def test_hex_dump_16_bytes_one_row():
    assert len(backend.format_hex_dump(b"A" * 16)) == 1

def test_hex_dump_17_bytes_two_rows():
    assert len(backend.format_hex_dump(b"A" * 17)) == 2



# TESTS FOR FUNCTION 5 — clear_data


def test_clear_empties_all_lists():
    backend.store_packet("12:00:00.000", "1.1.1.1", "2.2.2.2", "TCP", "80", "443", 100, b"x")
    backend.clear_data()
    assert len(backend.g_timestamps) == 0
    assert len(backend.g_src_ips)    == 0
    assert len(backend.g_dst_ips)    == 0
    assert len(backend.g_protocols)  == 0
    assert len(backend.g_src_ports)  == 0
    assert len(backend.g_dst_ports)  == 0
    assert len(backend.g_sizes)      == 0
    assert len(backend.g_raw_bytes)  == 0

def test_clear_resets_counters():
    backend.g_total = 5
    backend.g_tcp   = 3
    backend.g_udp   = 2
    backend.clear_data()
    assert backend.g_total == 0
    assert backend.g_tcp   == 0
    assert backend.g_udp   == 0
    assert backend.g_icmp  == 0
    assert backend.g_other == 0



# TESTS FOR start_capture / stop_capture


def test_start_capture_sets_is_sniffing_true():
    backend.clear_data()
    with patch("backend.threading.Thread") as mock_thread:
        mock_thread.return_value = MagicMock()
        backend.start_capture(None, 0)
        assert backend.is_sniffing == True
    backend.is_sniffing = False

def test_stop_capture_sets_is_sniffing_false():
    backend.is_sniffing = True
    backend.stop_capture()
    assert backend.is_sniffing == False

def test_start_capture_launches_thread():
    backend.clear_data()
    with patch("backend.threading.Thread") as mock_thread:
        instance = MagicMock()
        mock_thread.return_value = instance
        backend.start_capture("eth0", 10)
        instance.start.assert_called_once()
    backend.is_sniffing = False



# RUN ALL TESTS


if __name__ == "__main__":
    import sys

    all_tests = [
        # get_protocol_name
        test_tcp,
        test_udp,
        test_icmp,
        test_unknown_protocol,
        # store_packet
        test_store_packet_adds_to_lists,
        test_store_packet_correct_values,
        test_store_multiple_packets_lists_same_length,
        test_store_packet_index_in_sync,
        # format_hex_dump
        test_hex_dump_empty_bytes,
        test_hex_dump_returns_one_row,
        test_hex_dump_offset_starts_at_zero,
        test_hex_dump_second_row_offset_is_16,
        test_hex_dump_printable_chars_shown,
        test_hex_dump_non_printable_shown_as_dot,
        test_hex_dump_16_bytes_one_row,
        test_hex_dump_17_bytes_two_rows,
        # clear_data
        test_clear_empties_all_lists,
        test_clear_resets_counters,
        # start / stop capture
        test_start_capture_sets_is_sniffing_true,
        test_stop_capture_sets_is_sniffing_false,
        test_start_capture_launches_thread,
    ]

    passed = 0
    failed = 0

    for test in all_tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {test.__name__} — {e}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed out of {len(all_tests)} tests")
    sys.exit(0 if failed == 0 else 1)