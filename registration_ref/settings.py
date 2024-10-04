import os
from typing import Optional


def _env(name: str) -> str:
    try:
        return os.environ[name]
    except KeyError:
        raise RuntimeError("Missing required environment variable: {name}")


class class_property(property):
    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()


class Settings:
    @class_property  # type: ignore
    @staticmethod
    def DEVICE_GATEWAY_SERVER() -> str:
        return _env("DEVICE_GATEWAY_SERVER")

    @class_property  # type: ignore
    @staticmethod
    def OSTREE_SERVER() -> str:
        return _env("OSTREE_SERVER")

    @class_property  # type: ignore
    @staticmethod
    def CA_KEY() -> str:
        return _env("CA_KEY")

    @class_property  # type: ignore
    @staticmethod
    def CA_CRT() -> str:
        return _env("CA_CRT")

    @class_property  # type: ignore
    @staticmethod
    def ROOT_CRT() -> str:
        return _env("ROOT_CRT")

    @class_property  # type: ignore
    @staticmethod
    def DEVICES_DIR() -> str:
        return _env("DEVICES_DIR")

    @class_property  # type: ignore
    @staticmethod
    def DEVICE_GROUP() -> str:
        return _env("DEVICE_GROUP")

    @class_property  # type: ignore
    @staticmethod
    def API_TOKEN_PATH() -> Optional[str]:
        p = os.environ.get("FIO_API_TOKEN")
        if p and os.path.isfile(p):
            return p
        return None

    @class_property  # type: ignore
    @staticmethod
    def DEVICE_REGISTRATION_API() -> str:
        return os.getenv("DEVICE_REGISTRATION_API", "https://foundries.io/ota/devices/")

    @class_property  # type: ignore
    @staticmethod
    def VERIFY_SSL() -> bool:
        return os.getenv("VERIFY_SSL", "true").lower() in ("true", "1", "yes", "y")
