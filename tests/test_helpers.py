"""Tests for Utility Helpers"""

import os
import json
import tempfile
from utils.helpers import (
    validate_ip,
    format_bytes,
    get_protocol_name,
    save_state,
    load_state,
)


class TestValidateIp:
    def test_valid_ips(self):
        assert validate_ip('192.168.1.1')
        assert validate_ip('0.0.0.0')
        assert validate_ip('255.255.255.255')
        assert validate_ip('10.0.0.1')

    def test_invalid_ips(self):
        assert not validate_ip('256.0.0.1')
        assert not validate_ip('1.2.3')
        assert not validate_ip('1.2.3.4.5')
        assert not validate_ip('abc.def.ghi.jkl')
        assert not validate_ip('')

    def test_non_string_input(self):
        assert not validate_ip(None)


class TestFormatBytes:
    def test_bytes(self):
        assert format_bytes(500) == '500.00 B'

    def test_kilobytes(self):
        assert format_bytes(1024) == '1.00 KB'

    def test_megabytes(self):
        assert format_bytes(1024 * 1024) == '1.00 MB'

    def test_gigabytes(self):
        assert format_bytes(1024 ** 3) == '1.00 GB'


class TestGetProtocolName:
    def test_known_protocols(self):
        assert get_protocol_name(6) == 'TCP'
        assert get_protocol_name(17) == 'UDP'
        assert get_protocol_name(1) == 'ICMP'

    def test_unknown_protocol(self):
        result = get_protocol_name(999)
        assert '999' in result


class TestStatePersistence:
    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name

        try:
            data = {'key': 'value', 'count': 42}
            save_state(data, path)
            loaded = load_state(path)
            assert loaded == data
        finally:
            os.unlink(path)

    def test_load_nonexistent(self):
        result = load_state('/tmp/nonexistent_nids_state_12345.json')
        assert result is None
