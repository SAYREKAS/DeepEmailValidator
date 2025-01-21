"""Project configuration module."""

import os
import sys
from typing import Self, Literal
from urllib.parse import urlparse

from loguru import logger
from pydantic import BaseModel, model_validator, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def configure_logger(log_file: str) -> None:
    """
    Configures the logger to output logs to both the console and a file.
    Logs will be displayed in the console at the configured log level and saved to a rotating log file with compression.
    :param log_file: The name of the log file to store logs (e.g., "app.log").
    """

    logger.remove()
    logger.add(sys.stdout, level=settings.logs_level, colorize=True)
    logger.add(os.path.join(os.path.dirname(__file__), "logs", log_file), level=5, rotation="1 MB", compression="zip")


class ProxyParser(BaseModel):  # type: ignore
    url: str | None = None
    protocol: str | None = None
    username: str | None = None
    password: str | None = None
    server: str | None = None
    port: int | None = None

    @model_validator(mode="after")  # type: ignore
    def validate_url(self) -> Self:
        """Validate URL and parse its components"""

        if self.url is None:
            return self

        parsed_url = urlparse(self.url)

        # Protocol validation
        if parsed_url.scheme not in ["http", "https", "socks5"]:
            raise ValueError("URL must start with http:// or https:// or socks5://")
        self.protocol = parsed_url.scheme

        # Server validation
        if not parsed_url.hostname:
            raise ValueError("SERVER must be specified")
        self.server = parsed_url.hostname

        # Port handling (default if missing)
        self.port = parsed_url.port or (80 if self.protocol == "http" else 443)

        # Optional authorization
        self.username = parsed_url.username
        self.password = parsed_url.password

        # Validation if username is provided without password
        if self.username and not self.password:
            raise ValueError("PASSWORD must be provided if USERNAME is set")

        # Validation if password is provided without username
        if self.password and not self.username:
            raise ValueError("USERNAME must be provided if PASSWORD is set")

        return self


class Settings(BaseSettings):  # type: ignore
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="APP__",
        env_nested_delimiter="__",
    )
    proxy: ProxyParser | None = None
    dns_server_list: list[str] | None = None
    logs_level: Literal["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    @field_validator("dns_server_list", mode="before")  # type: ignore
    def parse_dns_servers_from_env(cls, value: str) -> list[str]:
        """Parse DNS server list from environment variable"""
        if value:
            return value.split(",")
        return ["8.8.8.8", "8.8.4.4"]  # default google dns


settings = Settings()
