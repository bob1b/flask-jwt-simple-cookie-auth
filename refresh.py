import logging
from flask import g

from . import jwt_manager
from . import tokens
from . import jwt_user
from .config import config

_logger = logging.getLogger(__name__)


def refresh_expiring_jwts(user_class=None):
    """
        Refresh access token for this request/session if it has expired

        In order to refresh access tokens:
            - we need a valid expired token which is also present in the Access Token table
            - we need an unexpired refresh token

        If the access token cannot be refreshed, both access and refresh tokens are unset
    """
    method = f'refresh_expiring_jwts()'

    if hasattr(g, 'checked_expiring') and g.checked_expiring == True: # already checked for expiring JWTs
        return
    g.checked_expiring = True

    enc_access_token , enc_refresh_token, csrf_tokens = tokens.get_tokens_from_cookies()

    if not enc_access_token or not enc_refresh_token or not csrf_tokens[0] or not csrf_tokens[1]:
        return

    user_id = tokens.get_jwt_identity()
    if not user_id:
        return

    user_obj = user_class.query.get(user_id)
    if not user_obj:
        _logger.error(f'{method}: could not find user object for cookie user id #{user_id}')
        g.unset_tokens = True
        return

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()

    access_token_obj = tokens.find_token_object_by_string(user_id, enc_access_token, token_class=access_token_class)
    refresh_token_obj = tokens.find_token_object_by_string(user_id, enc_refresh_token, token_class=refresh_token_class)

    if not access_token_obj:
        _logger.warning(
            f'{method}: no ACCESS TOKEN matching cookie. Cannot determine expiration nor refresh, user_id = {user_id}')
        g.unset_tokens = True
        return

    if not refresh_token_obj:
        _logger.warning(
            f'{method}: no REFRESH TOKEN matching cookie. Cannot refresh, user_id = {user_id}')
        g.unset_tokens = True
        return

    if not tokens.access_token_has_expired(access_token_obj):
        return

    # token hasn't yet expired, get the info so that we can further check validity
    opt = {
        "csrf_tokens": csrf_tokens,
        "enc_access_token": enc_access_token,
        "enc_refresh_token": enc_refresh_token,
    }
    dec_access_token, dec_refresh_token = tokens.decode_and_validate_tokens(opt)

    user_id = dec_access_token.get(config.get('JWT_IDENTITY_CLAIM'))
    expired_access_token = access_token_obj

    # user is not logged in, nothing to do
    if not dec_access_token:
        g.unset_tokens = True
        return

    # TODO - token_is_refreshable()
    # check if token cannot be refreshed (it is older than the refresh token)
    if tokens.access_token_has_expired(access_token_obj, use_refresh_expiration_delta=True):
        _logger.info(f'{method}: user #{user_id} access token cannot be refreshed because it is older than the ' +
                     'refresh token expiration')
        g.unset_tokens = True
        return

    jwt_man = jwt_manager.get_jwt_manager()
    _, refresh_token_class = jwt_man.get_token_classes()
    if tokens.refresh_token_has_expired(refresh_token_obj, refresh_token_class):
        _logger.info(f'{method}: user #{user_id} refresh token has expired. Access token cannot be refreshed')
        g.unset_tokens = True
        return

    # refresh the access token
    _logger.info(f'{method}: user #{user_id} {-1 * tokens.expires_in_seconds(expired_access_token)} seconds since access ' +
                 f"'token expiration. Refreshing access token ...")

    # TODO - is this the correct method to call here?
    access_token = jwt_user.create_or_update_user_access_token(user, update_existing=expired_access_token) # TODO - fix
    g.unset_tokens = False
    g.new_access_token = access_token

    # TODO - update current_user - XXX this might be causing the CSRF issue?
    # TODO - do we need this?
    # jwt_user.update_current_user()
    # jwt_data, jwt_header = validate_request_jwt()
    # jwt_user.update_current_user(jwt_header, jwt_data)
