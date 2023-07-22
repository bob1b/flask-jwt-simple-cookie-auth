import logging

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
