"""Pure-Python TCP connect port scan — fallback when nmap/naabu are unavailable.

Harmless (plain TCP connect, no raw packets) and dependency-free, so it works
on any platform and is never blocked by binary-reputation controls.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

# ~80 common ports with service labels.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1025: "msrpc", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2086: "whm", 2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
    2222: "ssh-alt", 3000: "http-dev", 3128: "proxy", 3306: "mysql", 3389: "rdp",
    4443: "https-alt", 5000: "http-dev", 5432: "postgres", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl", 6379: "redis",
    6443: "kube-api", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8083: "http-alt", 8088: "http-alt",
    8090: "http-alt", 8161: "activemq", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9042: "cassandra", 9200: "elasticsearch", 9300: "elastic",
    9443: "https-alt", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 5555: "http-alt", 8009: "ajp", 50070: "hadoop",
}


def scan(host, ports=None, timeout=1.5, workers=60):
    """Return a sorted list of (port, service) tuples that are open."""
    ports = ports or COMMON_PORTS

    def probe(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except OSError:
            return None
        return None

    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(probe, ports.keys()):
            if r:
                open_ports.append(r)
    open_ports.sort()
    return [(p, ports.get(p, "?")) for p in open_ports]
