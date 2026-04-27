from enum import Enum

class SupportedType(Enum):
    IP = "ip"
    EMAIL = "email"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
