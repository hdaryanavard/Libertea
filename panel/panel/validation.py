import hmac
import ipaddress
import re


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def is_valid_hostname(value):
    """Return whether value is a plain DNS hostname suitable for HAProxy/certbot."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    if value.endswith('.'):
        value = value[:-1]
    labels = value.split('.')
    if len(labels) < 2 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
        return False
    if all(label.isdigit() for label in labels):
        return is_valid_ipv4(value)
    return True


def is_valid_domain(value):
    return (is_valid_hostname(value) and not is_valid_ipv4(value)
            and not value.rstrip('.').split('.')[-1].isdigit())


def is_valid_ipv4(value):
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def bounded_int(value, default, minimum, maximum):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(value, minimum), maximum)


def secrets_equal(received, expected):
    if not isinstance(received, str) or not isinstance(expected, str):
        return False
    return hmac.compare_digest(received.encode('utf-8'), expected.encode('utf-8'))
