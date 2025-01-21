"""
DNS Resolver Module
This module provides functionality for performing DNS queries with optional SOCKS5 proxy support.
It allows querying various DNS record types using custom DNS servers.

Various DNS record types:
"A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA",
"CNAME", "PTR", "SRV", "NAPTR", "DNSKEY", "DS", "CDS", "TLSA", "DNAME", "HINFO", “RP”, "LOC", "AFSDB", "URI"
"""

import socks
import socket
import dns.resolver
from dns.resolver import Answer

from loguru import logger

from config import settings, configure_logger


configure_logger("dns_resolver.log")


def dns_resolver(domain: str, record_type: str) -> Answer:
    """
    Resolves the specified DNS record type for a given domain.

    The function queries the DNS servers defined in the settings and optionally uses a SOCKS5 proxy if configured.

    :param domain: The domain name to query (e.g., "example.com").
    :param record_type: The DNS record type to retrieve (e.g., "A", "MX", "TXT").
    :return: The DNS response containing the requested records.
    :raises Exception: If the DNS query fails.
    """

    logger.debug(f"Making DNS request for domain '{domain}' with record type '{record_type}'")
    original_socket = socket.socket  # Зберігаємо оригінальний сокет для відновлення

    try:
        if settings.proxy:
            logger.debug(f"Setting up SOCKS5 proxy for DNS request: {settings.proxy.server}:{settings.proxy.port}")
            socks.set_default_proxy(
                socks.SOCKS5,
                settings.proxy.server,
                settings.proxy.port,
                username=settings.proxy.username,
                password=settings.proxy.password,
            )
            socket.socket = socks.socksocket
            logger.debug("SOCKS5 proxy socket set successfully.")

        resolver = dns.resolver.Resolver()

        resolver.nameservers = settings.dns_server_list
        logger.debug(f"Using DNS servers: {resolver.nameservers}")

        answers = resolver.resolve(domain, record_type)
        logger.debug(f"DNS request successful for domain '{domain}', record type '{record_type}'")
        return answers

    except Exception as e:
        logger.debug(str(e))
        raise

    finally:
        if settings.proxy:
            socket.socket = original_socket
            logger.debug("Socket reset to original configuration.")
