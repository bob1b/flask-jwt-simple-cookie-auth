import jwt
import math
import logging
from flask import g
from typing import (Any, Optional)
from jwt import ExpiredSignatureError
from datetime import (datetime, timezone)

from . import utils
from . import jwt_manager
from . import tokens_encode_decode

from .config import config

_logger = logging.getLogger(__name__)


def get_jwt() -> dict:
    """
        This will return the python dict containing JWT payload of the client accessing the endpoint if "flask.g" has
        this value set. Otherwise, return None
    """
    return g.get("_jwt_extended_jwt", None)


def get_jwt_header() -> dict:
    """
        Return the python dictionary which has the header of the JWT that is accessing the endpoint, if "flask.g" has
        this value set. Otherwise, return None
    """
    return g.get("_jwt_extended_jwt_header", None)


def get_user_id_from_token(encoded_token: str = None) -> Optional[str]:
    return get_jwt_identity(tokens_encode_decode.decode_token(encoded_token))


def get_jwt_identity(access_token_dict: Optional[dict] = None, get_jwt_if_none: bool = True) -> Any:
    """
        In a protected endpoint, this will return the identity of the JWT that is accessing the endpoint. If no JWT is
        present due to ``jwt_sca(optional=True)``, ``None`` is returned. Returns the identity of the JWT in the current
        request
    """
    if not access_token_dict and get_jwt_if_none:
        access_token_dict = get_jwt()
        if not access_token_dict:
            return

    return access_token_dict.get(config.identity_claim_key, None)


# TODO - rewrite this method
def get_csrf_token_from_encoded_token(encoded_token: str) -> str: # TODO
    """
        Returns the CSRF double submit token from an encoded JWT.
          :param encoded_token:  The encoded JWT
          :return:  The CSRF double submit token (string)
    """

    token = tokens_encode_decode.decode_token(encoded_token)
    return token["csrf"]


def token_dict_expires_in_seconds(dec_token):
    return int(token_dict_expiration(dec_token) - datetime.timestamp(datetime.now(timezone.utc)))

def token_dict_expiration(dec_token):
    return int(dec_token["exp"])

def token_dict_issued_at(dec_token):
    return int(dec_token["iat"])


def expires_in_seconds(token_obj: Any,
                       no_exception: bool = True,
                       use_refresh_expiration_delta: bool = False) -> Optional[int]:
    """
        token_obj: a Token model (ie. Sqlalchemy) object

        TODO - probably want to allow external modules to set this method somehow so it'll match its own token model.
               For example, .token might not be the correct field name for token data in every app's Token model
   """
    method = 'expires_in_seconds()'

    jwt_man = jwt_manager.get_jwt_manager()

    try:
        dec_access_token = jwt.decode(token_obj.token,
                                      # secret=None, # TODO - jwt_man.encode_key_callback(identity),
                                      algorithms=config.decode_algorithms, options={"verify_signature": False})
    except Exception as e: # TODO - use correct exception name here and in token_has_expired()
        err = f'{method}: exception in jwt.decode(): {e}'
        _logger.error(err)
        if not no_exception:
            raise
        return

    expires_in = token_dict_expires_in_seconds(dec_access_token)

    # Use refresh token expiration for an access token. Used for determining if the access token is still refreshable
    access_token_class, _ = jwt_man.get_token_classes()

    if use_refresh_expiration_delta and isinstance(token_obj, access_token_class):
        # Adjust the expiration time from access delta to refresh delta
        expires_in = expires_in - config.access_expires.total_seconds() + config.refresh_expires.total_seconds()

    return expires_in


def access_token_has_expired(token_obj: object,
                             fresh_required: bool = False, # TODO
                             use_refresh_expiration_delta: bool = False) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj, use_refresh_expiration_delta=use_refresh_expiration_delta)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def access_token_obj_percent_expired(token_obj: object) -> float:
    token_dict = tokens_encode_decode.decode_token(token_obj.token, no_exception=True)
    total_token_duration_seconds = token_dict_expiration(token_dict) - token_dict_issued_at(token_dict)
    expires_in = token_dict_expires_in_seconds(token_dict)
    percent = math.ceil((float(total_token_duration_seconds - expires_in) / float(total_token_duration_seconds)) * 100.0)
    return percent


def refresh_token_has_expired(token_obj: Any) -> bool:
    try:
        expires_in = expires_in_seconds(token_obj)
        return expires_in <= 0
    except ExpiredSignatureError as e:
        return True


def is_time_to_refresh_the_access_token(token_obj: object) -> bool:
    """ check if token is expired enough that it can be refreshed """
    if not token_obj:
        _logger.warning("is_time_to_refresh_the_access_token(): no token")
        return False
    return access_token_obj_percent_expired(token_obj) >= config.access_refresh_after_percent_expired


def displayable_from_decoded_token(decoded_token: dict, token_object: Optional[object]=None) -> str:
    """ return a displayable decoded token format from a decoded token dict """
    """ example decoded dict: {'fresh': False, 'iat': 1696817640, 'jti': 'f2456a59-3bd3-4ae2-8f82-052f24ac5c20',
                                   'type': 'access', 'sub': 1, 'nbf': 1696817640,
                                   'csrf': 'a42a8d84-cca7-46a2-9819-c65fa0584416', 'exp': 1696817700} """
    if not decoded_token:
        return '<No token>'

    exp = f'{token_dict_expires_in_seconds(decoded_token)} sec'
    jti = decoded_token['jti']
    token_type = str(decoded_token['type']).upper()

    token_percent = ''
    if token_object:
        token_percent = f'/({access_token_obj_percent_expired(token_object)}%)'
    return f'<{token_type}: {exp}{token_percent} "{utils.shorten_middle(jti, 15)}">'


def displayable_from_encoded_token(encoded_token: str, token_object: Optional[object]=None) -> str:
    """ return a displayable decoded token format from an encoded token """
    token_dict = tokens_encode_decode.decode_token(encoded_token, no_exception=True)
    return displayable_from_decoded_token(token_dict, token_object=token_object)
