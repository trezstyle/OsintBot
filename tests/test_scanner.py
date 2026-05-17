"""Tests for scanner service."""
import pytest

from services.scanner import parse_nmap_hosts, format_scan


class TestParseNmapHosts:
    def test_single_host_ipv4(self):
        output = (
            "Nmap scan report for 192.168.1.1\n"
            "Host is up (0.0010s latency).\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "80/tcp   open  http\n"
        )
        hosts = parse_nmap_hosts(output)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.1"
        assert hosts[0]["hostname"] == "192.168.1.1"
        assert len(hosts[0]["ports"]) == 2
        assert hosts[0]["ports"][0]["port"] == "22/tcp"
        assert hosts[0]["ports"][1]["service"] == "http"

    def test_host_with_hostname(self):
        output = (
            "Nmap scan report for example.com (93.184.216.34)\n"
            "Host is up.\n"
            "PORT    STATE SERVICE\n"
            "443/tcp open  https\n"
        )
        hosts = parse_nmap_hosts(output)
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "example.com"
        assert hosts[0]["ip"] == "93.184.216.34"
        assert len(hosts[0]["ports"]) == 1

    def test_no_open_ports(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "Host is up.\n"
            "PORT     STATE  SERVICE\n"
            "22/tcp   closed ssh\n"
        )
        hosts = parse_nmap_hosts(output)
        assert len(hosts) == 1
        assert len(hosts[0]["ports"]) == 0

    def test_multiple_hosts(self):
        output = (
            "Nmap scan report for 10.0.0.1\n"
            "PORT     STATE SERVICE\n"
            "22/tcp   open  ssh\n"
            "Nmap scan report for 10.0.0.2\n"
            "PORT     STATE SERVICE\n"
            "80/tcp   open  http\n"
        )
        hosts = parse_nmap_hosts(output)
        assert len(hosts) == 2
        assert hosts[0]["ip"] == "10.0.0.1"
        assert hosts[1]["ip"] == "10.0.0.2"

    def test_empty_output(self):
        assert parse_nmap_hosts("") == []
        assert parse_nmap_hosts("No hosts found") == []


class TestFormatScan:
    def test_no_hosts(self):
        result = format_scan("10.0.0.1", "Nmap done: 1 host scanned", [])
        assert "No hosts found" in result

    def test_with_hosts(self):
        hosts = [{"hostname": "10.0.0.1", "ip": "10.0.0.1", "ports": [
            {"port": "22/tcp", "service": "ssh", "version": ""}
        ]}]
        result = format_scan("10.0.0.1", "Nmap done: 1 host scanned", hosts)
        assert "10.0.0.1" in result
        assert "22/tcp" in result
        assert "ssh" in result
