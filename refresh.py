import jwt
import json
import logging
from flask import g, current_app

from . import tokens
from . import jwt_user
from . import jwt_manager

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
        jwt_user.set_no_user()
        return

    jwt_man = jwt_manager.get_jwt_manager()
    access_token_class, refresh_token_class = jwt_man.get_token_classes()

    access_token_obj = tokens.find_token_object_by_string(user_id, enc_access_token, token_class=access_token_class)
    refresh_token_obj = tokens.find_token_object_by_string(user_id, enc_refresh_token, token_class=refresh_token_class)

    if not access_token_obj:
        _logger.warning(
            f'{method}: no ACCESS TOKEN matching cookie. Cannot determine expiration nor refresh, user_id = {user_id}')
        jwt_user.set_no_user()
        return

    if not refresh_token_obj:
        _logger.warning(
            f'{method}: no REFRESH TOKEN matching cookie. Cannot refresh, user_id = {user_id}')
        jwt_user.set_no_user()
        return

    # if the refresh token has expired, then we can't refresh the access token
    if tokens.refresh_token_has_expired(refresh_token_obj):
        _logger.info(f'{method}: user #{user_id} refresh token has expired. Access token cannot be refreshed')
        jwt_user.set_no_user()
        return

    # if the access token hasn't expired yet, then we don't need to do anything
    if not tokens.access_token_has_expired(access_token_obj):
        return

    # token has expired. Get more info so that we can refresh it
    expired_access_token = access_token_obj

    # check if token cannot be refreshed (it is older than the refresh token)
    if tokens.token_is_refreshable(expired_access_token):
        _logger.info(f'{method}: user #{user_id} access token cannot be refreshed because it is older than the ' +
                     'refresh token expiration')
        jwt_user.set_no_user()
        return

    dec_access_token, _ = tokens.decode_and_validate_tokens({
        'allow_expired': True,
        'auto_refresh': False, # since we are already refreshing the access token and just need the decoded data
        "csrf_tokens": csrf_tokens,
        "enc_access_token": enc_access_token,
        "enc_refresh_token": enc_refresh_token,
    })

    user_id = dec_access_token.get(current_app.config.get('JWT_IDENTITY_CLAIM')) # TODO - shouldn't this be kept in JWTManager?
    # TODO - validate the user_id, it should match the current_user
    user = None

    if not user_id:
        _logger.warning(f'{method}: unable to get user_id from decoded access token: {json.dumps(dec_access_token)}, ' +
                        'cannot refresh access token')
        jwt_user.set_no_user()
        return

    _logger.info(f'{method}: user #{user_id} {-1 * tokens.expires_in_seconds(expired_access_token)} seconds since ' +
                 f'access token expiration. Refreshing access token ...')

    # refresh the access token
    access_token = jwt_user.create_or_update_user_access_token(user, update_existing=expired_access_token)
    g.new_access_token = access_token
    # TODO - would we ever want to refresh the refresh token here?

    # update current_user
    jwt_header = jwt.get_unverified_header(access_token)
    jwt_user.set_current_user(jwt_header, dec_access_token)
