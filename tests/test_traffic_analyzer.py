"""Tests for Traffic Analyzer"""

from datetime import datetime
from analysis.traffic_analyzer import TrafficAnalyzer


class TestTrafficAnalyzer:
    def test_packet_counting(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        for _ in range(10):
            analyzer.analyze_packet(make_packet_info())
        assert analyzer.total_packets == 10

    def test_protocol_distribution(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        for _ in range(3):
            analyzer.analyze_packet(make_packet_info(protocol='TCP'))
        for _ in range(2):
            analyzer.analyze_packet(make_packet_info(protocol='UDP'))

        dist = analyzer.get_protocol_distribution()
        assert dist['TCP']['count'] == 3
        assert dist['UDP']['count'] == 2
        assert abs(dist['TCP']['percentage'] - 60.0) < 0.01

    def test_top_talkers(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        for _ in range(5):
            analyzer.analyze_packet(make_packet_info(src_ip='10.0.0.1'))
        for _ in range(3):
            analyzer.analyze_packet(make_packet_info(src_ip='10.0.0.2'))

        top = analyzer.get_top_talkers(2)
        assert top[0] == ('10.0.0.1', 5)
        assert top[1] == ('10.0.0.2', 3)

    def test_top_ports(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        for _ in range(4):
            analyzer.analyze_packet(make_packet_info(dst_port=443))
        for _ in range(2):
            analyzer.analyze_packet(make_packet_info(dst_port=80))

        top = analyzer.get_top_ports(2)
        assert top[0] == (443, 4)
        assert top[1] == (80, 2)

    def test_average_packet_size(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        analyzer.analyze_packet(make_packet_info(packet_size=100))
        analyzer.analyze_packet(make_packet_info(packet_size=200))
        assert analyzer.get_average_packet_size() == 150.0

    def test_unique_ips_tracked(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        analyzer.analyze_packet(make_packet_info(src_ip='10.0.0.1', dst_ip='10.0.0.2'))
        analyzer.analyze_packet(make_packet_info(src_ip='10.0.0.1', dst_ip='10.0.0.3'))
        analyzer.analyze_packet(make_packet_info(src_ip='10.0.0.5', dst_ip='10.0.0.2'))

        assert len(analyzer.unique_src_ips) == 2
        assert len(analyzer.unique_dst_ips) == 2

    def test_port_name_lookup(self, base_config):
        analyzer = TrafficAnalyzer(base_config)
        assert analyzer.get_port_name(80) == 'HTTP'
        assert analyzer.get_port_name(443) == 'HTTPS'
        assert analyzer.get_port_name(99999) == 'Unknown'

    def test_summary_structure(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        analyzer.analyze_packet(make_packet_info())
        summary = analyzer.get_summary()

        assert 'total_packets' in summary
        assert 'traffic_rate' in summary
        assert 'protocol_distribution' in summary
        assert summary['total_packets'] == 1

    def test_bounded_packet_sizes(self, base_config, make_packet_info):
        analyzer = TrafficAnalyzer(base_config)
        assert analyzer.packet_sizes.maxlen == 100000
