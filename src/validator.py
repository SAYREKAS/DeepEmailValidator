"""
Module for email address validation and analysis.

This module provides a set of utilities to validate email addresses, check their domain's MX (Mail Exchange) records,
SPF, DKIM, DMARC records, and perform additional checks like blacklisting and catch-all functionality.
It uses DNS queries, SMTP checks, and caching to optimize the validation process.

Classes:
    EmailValidator: A class for validating and analyzing email addresses and their domains.

Functions:
    - black_list_check: Checks if the domain is blacklisted.
    - symbol_or_char_check: Validates the local part for invalid characters.
    - mx_check: Verifies if MX records exist for the domain.
    - mx_availability_check: Checks if MX servers are available.
    - spf_check: Checks the SPF record for the domain.
    - dkim_check: Verifies DKIM records for the domain.
    - catch_all_check: Detects if the domain has a catch-all functionality.
    - dmarc_check: Checks if the domain has a valid DMARC record.
"""

import re
import random
import string

from loguru import logger
from dns.resolver import NXDOMAIN, NoAnswer
from email_validator import validate_email, ValidatedEmail

from config import configure_logger
from src.utils.dns_resolver import dns_resolver
from src.utils.smtp_checker import smtp_checker
from src.utils.common import extract_email_provider
from src.utils.blacklist import ALL_BLACKLISTED_DOMAINS
from src.utils.cache import MXAvailabilityCache, DMARCCache, CatchAllCache, DKIMCache, SPFCache

configure_logger("validator.log")

mx_ok_cache = MXAvailabilityCache()
spf_cache = SPFCache()
dkim_cache = DKIMCache()
catch_all_cache = CatchAllCache()
dmarc_cache = DMARCCache()


class EmailValidator:
    """
    A class to validate and analyze email addresses.

    Attributes:
        full_email (str): The normalized email address.
        local_part (str): The local part of the email address.
        domain (str): The domain part of the email address.
        mx (set[str]): Set of MX records for the domain.
        good_mx (list[str]): List of verified good MX records.
        catch_all (set[str]): Set of domains with catch-all enabled.
        not_catch_all (set[str]): Set of domains without catch-all.
        spf (str | None): SPF record for the domain, if available.
        dkim (str | None): DKIM record for the domain, if available.
        provider (str | None): Email provider name, if detected.
    """

    def __init__(self, email_address: str) -> None:
        """
        Initializes the EmailValidator with the provided email address.

        :param email_address: The email address to validate and analyze.
        """
        logger.info(f"Initializing EmailValidator for email '{email_address}'")

        self._validated_email: ValidatedEmail = validate_email(
            email_address.lower(),
            check_deliverability=False,
            allow_smtputf8=False,
        )

        self.full_email: str = self._validated_email.normalized
        self.local_part: str = self._validated_email.local_part
        self.domain: str = self._validated_email.domain

        self.mx: list[str] = []
        self.good_mx: list[str] = []
        self.catch_all: list[str] = []
        self.not_catch_all: list[str] = []

        self.spf: str | None = None
        self.dkim: str | None = None
        self.provider: str | None = None

    def __repr__(self) -> str:
        """
        Returns a string representation of the EmailValidator instance.
        Excludes private attributes from the representation.
        """
        public_attrs = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        return f"{self.__class__.__name__}({public_attrs})"

    def black_list_check(self) -> bool:
        """
        Checks if the email domain is blacklisted.

        :return: False if the domain is blacklisted, otherwise True.
        """
        logger.info(f"Checking if the domain '{self.domain}' is blacklisted.")

        if self.domain in ALL_BLACKLISTED_DOMAINS:
            logger.warning(f"Domain '{self.domain}' is blacklisted.")
            return False

        logger.success(f"Domain '{self.domain}' is not blacklisted.")
        return True

    def symbol_or_char_check(self) -> bool:
        """
        Checks if the email's local part contains any invalid symbols or characters.

        :return: False if invalid symbols or characters are found, otherwise True.
        """
        logger.info(f"Checking for invalid symbols or characters in '{self.full_email}'.")

        if re.search(r"[^a-zA-Z.@-]", self.local_part):
            logger.error(f"Email '{self.full_email}' contains invalid symbols or characters.")
            return False

        logger.success(f"Email '{self.full_email}' contains only valid characters.")
        return True

    def mx_check(self) -> bool:
        """
        Checks if MX (Mail Exchange) records exist for the email domain.

        :return: True if MX records exist, otherwise False.
        """
        logger.info(f"Checking if MX records exist for '{self.full_email}'.")

        self.mx = [str(mx[1]) for mx in validate_email(self.full_email).mx]
        if self.mx:
            logger.success(f"MX records for '{self.full_email}' found: {self.mx}.")
            return True

        logger.warning(f"No MX records found for '{self.full_email}'.")
        return False

    def mx_availability_check(self) -> bool:
        """
        Checks the availability of MX servers for the email.
        Caches the result and performs verification via SMTP.

        :return: True if at least one MX server is available, otherwise False.
        """
        logger.info(f"Checking MX server availability for email '{self.full_email}'.")

        try:
            if not self.mx:
                if not self.mx_check():
                    logger.warning(f"No MX records found for '{self.full_email}'.")
                    return False

            for mx in self.mx:
                smtp_result = smtp_checker.requests(
                    mx_server=mx,
                    email=self.full_email,
                    domain=self.domain,
                    rcpt_to=True,
                )

                if smtp_result:
                    self.good_mx.append(mx)
                    logger.debug(f"MX server '{mx}' is available. Good MX count: {len(self.good_mx)}.")
                    self.provider = extract_email_provider(mx_server=mx)
                else:
                    logger.debug(f"MX server '{mx}' is not responding.")

            if self.good_mx:
                logger.success(f"MX availability check passed. Good MX count: {len(self.good_mx)}.")
                mx_ok_cache.set(key=self.domain, value=self.good_mx)
                return True

            logger.warning(f"All MX servers for '{self.full_email}' are unavailable.")
            return False

        except Exception as e:
            logger.critical(f"Unexpected error during MX availability check for '{self.full_email}': {e}")
            return False

    def spf_check(self) -> bool:
        """
        Checks the SPF (Sender Policy Framework) record for the domain.

        :return: True if an SPF record is found, otherwise False.
        """
        logger.info(f"Checking SPF record for domain '{self.domain}'.")

        try:
            answers = dns_resolver(domain=self.domain, record_type="TXT")
            for rdata in answers:
                txt_record = str(rdata)
                if "v=spf1" in txt_record:
                    self.spf = txt_record
                    logger.success(f"SPF record found: {txt_record}.")
                    spf_cache.set(key=self.domain, value=txt_record)
                    return True

            logger.warning(f"No SPF record found for domain '{self.domain}'.")
            return False

        except Exception as e:
            logger.error(f"SPF check failed for domain '{self.domain}': {e}")
            return False

    def dkim_check(self) -> bool:
        """
        Checks for DKIM (DomainKeys Identified Mail) records for the domain using common selectors.

        :return: True if a DKIM record is found, otherwise False.
        """
        logger.info(f"Checking DKIM records for domain '{self.domain}'.")

        selectors = [
            "google",
            "selector1",
            "default",
            "20161025",
            "selector2",
            "s1",
            "s2",
            "s3",
            "mail",
            "dkim",
            "smtp",
            "s2048",
            "s1024",
        ]
        patterns = ["v=DKIM1", "k=rsa", "t=s", "t=y", "p="]

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{self.domain}"

            try:
                answers = dns_resolver(domain=dkim_domain, record_type="TXT")
                for rdata in answers:
                    txt_record = str(rdata)
                    if any(pattern in txt_record for pattern in patterns):
                        self.dkim = txt_record
                        logger.success(f"DKIM record found for '{dkim_domain}': {txt_record}")
                        dkim_cache.set(key=self.domain, value=txt_record)
                        return True

            except NXDOMAIN:
                logger.debug(f"DKIM domain '{dkim_domain}' does not exist.")
            except NoAnswer:
                logger.warning(f"No DKIM record found for '{dkim_domain}'.")

        logger.warning(f"No DKIM records found for domain '{self.domain}'.")
        return False

    def catch_all_check(self) -> bool:
        """
        Checks the first available MX server for catch-all functionality.

        :raises: Exception if an unexpected error occurs during the check.
        """
        logger.info(f"Checking for catch-all server for domain '{self.domain}'.")

        try:
            if not self.good_mx:
                if not self.mx_availability_check():
                    logger.error(f"No available MX servers for domain '{self.domain}'.")
                    return False

            for mx in self.good_mx:
                random_address = (
                    f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=15))}@{self.domain}"
                )
                logger.debug(f"Generated random email address for check: {random_address}")
                logger.debug(f"Using MX server '{mx}' for catch-all check.")

                result = smtp_checker.requests(
                    mx_server=mx,
                    email=random_address,
                    domain=self.domain,
                    rcpt_to=True,
                )

                if result == 250:
                    logger.debug(f"Catch-all detected on MX server '{mx}' for domain '{self.domain}'.")
                    self.catch_all.append(mx)
                    catch_all_cache.set(key=mx, value=True)
                else:
                    logger.debug(f"Catch-all not detected on MX server '{mx}' for domain '{self.domain}'.")
                    self.not_catch_all.append(mx)

            if self.not_catch_all and not self.catch_all:
                logger.success(f"Catch-all not detected for domain '{self.domain}'.")
                return True

            if self.catch_all and not self.not_catch_all:
                logger.warning(f"All servers are catch-all for domain '{self.domain}'.")
                return False

            if self.catch_all and self.not_catch_all:
                logger.warning(f"Mixed results for catch-all check on domain '{self.domain}'. Returning False.")
                return False

        except Exception as e:
            logger.critical(f"Unexpected error during catch-all check for domain '{self.domain}': {e}")
            return False

    def dmarc_check(self) -> bool:
        """
        Checks for the presence of a DMARC record for the domain.
        Uses caching and DNS queries to optimize performance.

        :return: True if a DMARC record is found, otherwise False.
        """
        logger.info(f"Checking DMARC records for domain '{self.domain}'")
        dmarc_domain = f"_dmarc.{self.domain}"

        try:
            # Perform DNS query to retrieve TXT records
            answers = dns_resolver(domain=dmarc_domain, record_type="TXT")

            if not answers:
                logger.warning(f"No DMARC record found for domain '{self.domain}'.")
                return False

            # Check each TXT record for the DMARC entry
            for rdata in answers:
                txt_record = str(rdata)  # Convert response to string if necessary
                if "v=DMARC1" in txt_record:
                    logger.success(f"DMARC record found for domain '{dmarc_domain}': {txt_record}.")
                    dmarc_cache.set(self.domain, txt_record)
                    return True

            # If no valid DMARC record is found
            logger.warning(f"No DMARC record found for domain '{self.domain}'.")
            return False

        except Exception as e:
            logger.error(f"Error during DMARC check for domain '{self.domain}': {e}")
            return False
