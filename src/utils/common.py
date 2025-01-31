"""Common functions"""

from loguru import logger


def extract_email_provider(mx_server: str) -> str:
    """
    Extracts the email provider from an MX server address.

    :param mx_server: The MX server address (e.g., 'mx.gmail.com').
    :return: The extracted email provider (e.g., 'gmail.com').
    """
    logger.debug(f"Extracting email provider from MX server: '{mx_server}'")

    try:
        provider = ".".join(mx_server.split(".")[-2:])
        logger.debug(f"Successfully extracted provider '{provider}' from MX server '{mx_server}'")
        return provider

    except Exception as e:
        logger.error(f"Failed to extract provider from MX server '{mx_server}': {str(e)}")
        raise
