import logging
from flask import g

_logger = logging.getLogger(__name__)


def shorten(value, max_len=None):
    if value is None or value == '':
        return ''
    length = len(value)
    if max_len is None:
        max_len = 30
    if length <= max_len or max_len < 5:
        return value
    first_part_len = -(-max_len - 3) // 2  # round up division using two minuses
    last_part_len = (max_len - 3) - first_part_len
    first_part = value[:first_part_len]
    last_part = value[-last_part_len:]
    return f"{first_part}...{last_part}"


def clear_g_data():
    """
        Clears values we are saving in "flask.g" that could potentially persist across requests. In most cases, this
        should not be needed
    """
    for attr_name in ['_jwt_extended_jwt_user', '_jwt_extended_jwt_header', '_jwt_extended_jwt', 'new_access_token',
                      'new_refresh_token', 'unset_tokens', 'checked_expiring']:
        g.pop(attr_name, None)
