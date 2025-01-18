"""Project configuration module."""

import os.path
from typing import Self
from urllib.parse import urlparse

from pydantic import model_validator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxyParser(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_prefix="APP__PROXY__",
        env_nested_delimiter="__",
    )

    url: str = Field(description="An expected format: 'protocol://username:password@proxy.example.com:8443'")
    protocol: str | None = None
    username: str | None = None
    password: str | None = None
    server: str | None = None
    port: int | None = None

    @model_validator(mode="after")
    def validate_url(self) -> Self:
        """Validate URL and parse its components"""

        parsed_url = urlparse(self.url)

        # Protocol validation
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError("URL must start with http:// or https://")
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
