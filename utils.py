import sys
import logging
from .tokens_utils import token_dict_expires_in_seconds
from .tokens_encode_decode import decode_token
from flask import (g, current_app, Flask)


_logger = logging.getLogger(__name__)

def is_flask_shell():
    if len(sys.argv) > 1:
        return sys.argv[1] == 'shell'
    return False

def shorten_middle(value, max_len=30, placeholder='...'):
    if value is None or value == '':
        return ''
    if len(value) <= max_len or max_len < (len(placeholder) + 2):
        return value
    max_len_minus_placeholder = max_len - len(placeholder)
    last_part_len = max_len_minus_placeholder // 2  # round up division
    first_part_len = max_len_minus_placeholder - last_part_len
    return f"{value[:first_part_len]}{placeholder}{value[-last_part_len:]}"


def clear_g_data():
    """
        Clears values we are saving in "flask.g" that could potentially persist across requests. In most cases, this
        should not be needed
    """
    for attr_name in ['_jwt_extended_jwt_user', '_jwt_extended_jwt_header', '_jwt_extended_jwt', 'new_access_token',
                      'new_refresh_token', 'unset_tokens', 'checking_expiring']:
        g.pop(attr_name, None)
