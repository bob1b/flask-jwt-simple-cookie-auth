import logging
from flask import (g, make_response)
from . import utils
from . import tokens_cookies

_logger = logging.getLogger(__name__)


def after_request(response):
    """ If tokens were refreshed during this request, then set the new access token response cookie """
    method = 'after_request()'

    # if we have a tuple like `(<response_value: dict>, <status_code: int>)`
    if isinstance(response, tuple) and len(response) == 2:
        response = make_response(response[0], response[1])

    elif isinstance(response, (str, dict)):
        response = make_response(response)

    if hasattr(g, "new_access_token"):
        _logger.info(f"{method}: g.new_access_token = {utils.shorten_middle(g.new_access_token, 40)} ***")
        tokens_cookies.set_access_cookies(response, g.new_access_token)

    if hasattr(g, "new_refresh_token"):
        _logger.info(f"{method}: g.new_refresh_token = {utils.shorten_middle(g.new_refresh_token, 40)} ***")
        tokens_cookies.set_refresh_cookies(response, g.new_refresh_token)

    # Unset jwt cookies in the response (e.g. user logged out)
    if hasattr(g, "unset_tokens") and g.unset_tokens:
        _logger.info(f"{method}: g.unset tokens = {g.unset_tokens} *** ")
        tokens_cookies.unset_jwt_cookies(response)

    return response
