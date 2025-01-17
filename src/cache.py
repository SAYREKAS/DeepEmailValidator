"""Module for managing JSON-based cache storage with specialized caches for MX, SPF, DKIM, DMARC, and other email-related records."""

import os
import json

from loguru import logger


class CacheBase:
    """Base class for handling JSON-based cache storage."""

    def __init__(self, filename: str = "cache.json", cache_dir: str = "cache") -> None:
        self.filename = filename
        self.cache_dir = cache_dir
        self.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.cache_dir)
        if not os.path.exists(self.cache_path):
            os.makedirs(self.cache_path)
        self.__load_cache()

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} size: {self.size}"

    def __load_cache(self) -> None:
        """
        Loads the cache from the JSON file if it exists, otherwise initializes an empty cache.
        """

        cache_file = os.path.join(self.cache_path, self.filename)
        try:
            with open(cache_file) as file:
                self.__cache = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            self.__cache = {}

    def __save_cache(self) -> None:
        """
        Saves the current cache to the JSON file.
        """

        cache_file = os.path.join(self.cache_path, self.filename)
        with open(cache_file, "w") as file:
            json.dump(self.__cache, file)

    def get(self, key: str) -> str | None:
        """
        Retrieves a value from the cache by key.

        :param key: The key to look up in the cache.
        :return: The value associated with the key, or None if the key does not exist.
        """

        value: str | None = self.__cache.get(key)
        logger.debug(f"Getting key '{key}': {value}")
        return value

    def set(self, key: str, value: str) -> None:
        """
        Sets a value in the cache with the specified key.

        :param key: The key under which to store the value.
        :param value: The value to store.
        """

        self.__cache[key] = value
        self.__save_cache()
        logger.debug(f"Setting key '{key}' to value '{value}'")

    def clear(self) -> None:
        """Clears all entries in the cache."""

        self.__cache.clear()
        self.__save_cache()
        logger.debug("Cache cleared.")

    def size(self) -> int:
        """
        Returns the number of entries in the cache.

        :return: The number of cache entries.
        """

        size = len(self.__cache)
        logger.debug(f"Cache size: {size}")
        return size


class MXCache(CacheBase):
    """Cache for storing MX record data."""

    def __init__(self, filename: str = "mx_cache.json"):
        super().__init__(filename=filename)


class SPFCache(CacheBase):
    """Cache for storing SPF record data."""

    def __init__(self, filename: str = "spf_cache.json"):
        super().__init__(filename=filename)


class DKIMCache(CacheBase):
    """Cache for storing DKIM record data."""

    def __init__(self, filename: str = "dkim_cache.json"):
        super().__init__(filename=filename)


class DMARCCache(CacheBase):
    """Cache for storing DMARC record data."""

    def __init__(self, filename: str = "dmarc_cache.json"):
        super().__init__(filename=filename)


class CatchAllCache(CacheBase):
    """Cache for storing catch-all domain status data."""

    def __init__(self, filename: str = "catchall_cache.json"):
        super().__init__(filename=filename)


class MXAvailabilityCache(CacheBase):
    """Cache for storing MX server availability data."""

    def __init__(self, filename: str = "mx_availability_cache.json"):
        super().__init__(filename=filename)
