"""A module for validating email addresses via SMTP requests with optional SOCKS5 proxy support."""

import smtplib

import socket
from loguru import logger
from pydantic import BaseModel, Field

from config import configure_logger

configure_logger("smtp_checker.log")


class ResolvedIPs(BaseModel):  # type: ignore
    v4: str = Field(default="")
    v6: str = Field(default="")


def resolve_server_ip(domain: str, port: int = 25) -> ResolvedIPs:
    """
    Resolve the IPv4 and IPv6 addresses for the specified domain and port.

    This function uses the `socket.getaddrinfo` method to retrieve both IPv4 and IPv6
    addresses for the given domain on the specified port. If resolution fails for
    either IPv4 or IPv6, a warning is logged. By default, port 25 (SMTP) is used.

    :param domain: The domain name to resolve.
    :param port: The port number for which to resolve the addresses (default is 25).

    :return:
        ResolvedIPs: An object containing the resolved IPv4 and IPv6 addresses.
                     If resolution fails for an address type, the corresponding field
                     will remain an empty string.
    """

    result = ResolvedIPs()
    try:
        # IPv4
        addr_info_v4 = socket.getaddrinfo(domain, port, socket.AF_INET, socket.SOCK_STREAM)
        result.v4 = addr_info_v4[0][4][0]
    except socket.gaierror as e:
        logger.debug("Failed to resolve IPv4 for domain '{}': {}", domain, str(e))

    try:
        # IPv6
        addr_info_v6 = socket.getaddrinfo(domain, port, socket.AF_INET6, socket.SOCK_STREAM)
        result.v6 = addr_info_v6[0][4][0]
    except socket.gaierror as e:
        logger.debug("Failed to resolve IPv6 for domain '{}': {}", domain, str(e))

    logger.debug("Resolved IP addresses for domain '{}': {}", domain, result)
    return result


class SMTPChecker:
    """
    A utility class for performing SMTP requests to validate email addresses.

    This class provides methods to:
    - Connect to an MX server and perform the HELO command.
    - Execute the MAIL FROM command to verify the sender's domain.
    - Execute the RCPT TO command to validate the recipient's email address.

    The main `requests` method orchestrates the email validation process,
    optionally supporting proxy usage and recipient validation.
    """

    @staticmethod
    def _connect_and_helo_to_mx_server(server: smtplib.SMTP) -> bool:
        """Connect to the MX server and perform HELO command"""

        try:
            # Execute the HELO command, which is standard when connecting to the SMTP server.
            code, message = server.helo("domain.online")
            logger.debug("HELO command response: {}, {}", code, message)

            # Testing the success of the HELO team. Usually responds with code 250.
            if code != 250:
                logger.debug("HELO EHLO error: {}", message)
                return False

            return True

        except smtplib.SMTPException as e:
            logger.debug("Error during HELO command: {}", str(e))
            return False

    @staticmethod
    def _send_mail_from_command(server: smtplib.SMTP, domain: str) -> bool:
        """Send MAIL FROM command to the server"""

        try:
            # Sending the MAIL FROM command to identify the sender
            code, message = server.mail(f"postmaster@{domain}")
            logger.debug("MAIL FROM command response: {}, {}", code, message)

            # Checking the success of the MAIL FROM command
            if code != 250:
                return False

            return True

        except smtplib.SMTPException as e:
            logger.debug("MAIL FROM command failed: {}", str(e))
            return False

    @staticmethod
    def _send_rcpt_to_command(server: smtplib.SMTP, email_address: str) -> bool:
        """Send RCPT TO command to the server"""

        try:
            # Sending an RCPT TO command to verify the recipient
            code, message = server.rcpt(email_address)
            logger.debug("RCPT TO command response: {}, {}", code, message)

            # Checking the success of the RCPT TO team
            if code != 250:
                # Additional logging for different types of blocking
                if "spamhaus" in str(message).lower():
                    logger.debug("Blocked by Spamhaus: {}", message)

                elif "banned sending ip" in str(message).lower():
                    logger.debug("Banned sending IP: {}", message)

                elif "blocked - see https://ipcheck.proofpoint" in str(message).lower():
                    logger.debug("Banned sending IP (ProofPoint): {}", message)

                else:
                    logger.debug("RCPT TO error: {}", message)

                return False

            return True

        except smtplib.SMTPException as e:
            logger.debug("RCPT TO command failed: {}", str(e))
            return False

    def requests(self, mx_server: str, email: str, domain: str, rcpt_to: bool = False) -> bool:
        """Main method to validate email through SMTP"""

        logger.debug("Starting SMTP request to MX server '{}' for email '{}'", mx_server, email)

        resolved_ips = resolve_server_ip(domain=mx_server)
        if not resolved_ips.v6 and not resolved_ips.v4:
            logger.debug("MX server '{}' does not have IPv4 or IPv6 address", mx_server)
            return False

        ip_address: str = resolved_ips.v6 or resolved_ips.v4

        try:
            logger.debug("Connecting to SMTP server at {} with timeout 10 seconds.", ip_address)

            with smtplib.SMTP(ip_address, timeout=10) as server:
                if not self._connect_and_helo_to_mx_server(server=server):
                    return False

                if not self._send_mail_from_command(server=server, domain=domain):
                    return False

                if rcpt_to and not self._send_rcpt_to_command(server=server, email_address=email):
                    return False

                logger.debug("SMTP validation completed successfully")
                return True

        except smtplib.SMTPException as e:
            logger.debug("SMTP validation failed: {}", str(e))
            return False

        except TimeoutError:
            logger.debug("SMTP request timed out")
            return False


smtp_checker = SMTPChecker()
