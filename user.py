from datetime import timedelta
from flask import g
from typing import (Any, Optional, Type, TYPE_CHECKING)
from .utils import (get_access_cookie_value, get_refresh_cookie_value)
from .config import config
from .tokens import (create_refresh_token, get_jwt)
from .exceptions import UserLookupError
from .jwt_manager import get_jwt_manager


def login(user, request):
    # create cookies and save in 'g' so they will be applied to the response
    g.new_access_token = user.create_access_token(request=request, fresh=timedelta(minutes=15))
    g.new_refresh_token = user.create_refresh_token()
    # TODO


def logout_user(user, response=None, logout_all_sessions=False):
    method = f'logout_user({user.id}, response={response}, logout_all_sessions={logout_all_sessions})'

    if not logout_all_sessions:  # if we logged out all sessions, then all tokens have already been removed
        tokens = []

        access_cookie_value = get_access_cookie_value()
        if not access_cookie_value:
            _logger.warning(f'{method}: no access_cookie_value for user #{user.id}, cannot invalidate access token')
        else:
            found_tokens = models.AccessToken.query.filter_by(user_id=user.id, token=access_cookie_value).all()  # TODO
            if not found_tokens:
                _logger.warning(f'{method}: no AccessToken(s) found for cookie value "{access_cookie_value}", ' +
                                f'user #{user.id}')
            else:
                tokens = tokens + found_tokens

        refresh_cookie_value = get_refresh_cookie_value()
        if not refresh_cookie_value:
            _logger.warning(
                f'{method}: no refresh_cookie_value for user #{user.id}, cannot invalidate access token')
        else:
            found_tokens = models.RefreshToken.query.filter_by(  # TODO
                user_id=user.id, token=refresh_cookie_value).all()
            if not found_tokens:
                _logger.warning(
                    f'{method}: no RefreshToken(s) found for cookie value "{refresh_cookie_value}", ' +
                    f'user #{user.id}')
            else:
                tokens = tokens + found_tokens

        for token in tokens:
            _logger.info(f'{method}: deleting token: {token}')
            db.session.delete(token)  # TODO
        db.session.commit()

        g.unset_tokens = True


def remove_user_expired_tokens(user):
    """
        Remove expired tokens for this user. Even though Access Tokens expire relatively quickly compared to
          Refresh Tokens, only consider tokens to be expired if they are older than the Refresh Token expiration.

        Otherwise, we might end up deleting still in-use Access Tokens if the user has multiple sessions of the same
          login across multiple devices
    """
    method = f'remove_expired_tokens(user #{user.id} ({user.email}))'
    removed_access_count = 0
    removed_refresh_count = 0
    user_tokens = models.AccessToken.query.filter_by(user_id=user.id).all() + \
                  models.RefreshToken.query.filter_by(user_id=user.id).all()
    for token in user_tokens:
        expires_in_seconds = token.expires_in_seconds(use_refresh_expiration_delta=True)
        if int(expires_in_seconds) < 0:
            if type(token) == models.AccessToken:
                removed_access_count = removed_access_count + 1
            else: # refresh token
                removed_refresh_count = removed_refresh_count + 1
            db.session.delete(token)
    db.session.commit()
    _logger.info(f'{method}: removed {removed_access_count} expired access tokens and {removed_refresh_count } ' +
                 'refresh tokens')


def create_user_access_token(self, request=None, fresh=False, expires_delta=timedelta(minutes=15), replace=None):
    method = f"User.create_access_token({self})"

    user_agent = None
    if request:
        user_agent = request.headers.get("User-Agent")

    access_token = jwt2.create_access_token(identity=self.id, fresh=fresh) # set JWT access cookie (includes CSRF)

    _logger.info(f"{method}: Created new access_token = {access_token}")

    if replace and type(replace) == models.AccessToken:
        replace.token = access_token
        replace.user_agent = user_agent
    else:
        access_token_obj = models.AccessToken(token=access_token, user_id=self.id, user_agent=user_agent)
        db.session.add(access_token_obj)
    db.session.commit()
    return access_token


def create_user_refresh_token(self, expires_delta=timedelta(weeks=2)):
    refresh_token = create_refresh_token(identity=self.id)
    refresh_token_obj = models.RefreshToken(token=refresh_token, user_id=self.id)  # TODO
    db.session.add(refresh_token_obj)
    db.session.commit()
    return refresh_token


def _load_user(jwt_header: dict, jwt_data: dict) -> Optional[dict]:
    if not has_user_lookup():
        return None

    identity = jwt_data[config.identity_claim_key]
    user = user_lookup(jwt_header, jwt_data)
    if user is None:
        error_msg = f"user_lookup returned None for {identity}"
        raise UserLookupError(error_msg, jwt_header, jwt_data)
    return {"loaded_user": user}


def has_user_lookup() -> bool:
    jwt_manager = get_jwt_manager()
    return jwt_manager.user_lookup_callback is not None


def user_lookup(*args, **kwargs) -> Any:
    jwt_manager = get_jwt_manager()
    return jwt_manager.user_lookup_callback and jwt_manager.user_lookup_callback(*args, **kwargs)


def get_current_user() -> Any:
    """
        In a protected endpoint, this will return the user object for the JWT that is accessing the endpoint.

        This is only usable if :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader` is configured. If the user
        loader callback is not being used, this will raise an error.

        If no JWT is present due to ``jwt_sca(optional=True)``, ``None`` is returned.

        :return:
            The current user object for the JWT in the current request
    """

    get_jwt()  # Raise an error if not in a decorated context

    # tokens had expired at beginning of this request
    if hasattr(g, 'unset_tokens') and g.unset_tokens:
        _logger.info('current_user(): got g.unset_tokens, returning no-user')
        return None

    jwt_user_dict = g.get("_jwt_extended_jwt_user", None)
    if jwt_user_dict is None:
        raise RuntimeError("You must provide a `@jwt.user_lookup_loader` callback to use this method")
    return jwt_user_dict["loaded_user"]

# TODO - might not need this
# def set_current_user_from_token_string(access_token_string=False):
#     try:
#         # jwt_manager = get_jwt_manager()
#         jwt_dict = _decode_jwt(encoded_token=access_token_string)
#     except (NoAuthorizationError, ExpiredSignatureError) as e:
#         if type(e) == NoAuthorizationError and not optional:
#             raise
#         if type(e) == ExpiredSignatureError and not no_exception_on_expired:
#             raise
#         g._jwt_extended_jwt = {}
#         g._jwt_extended_jwt_header = {}
#         g._jwt_extended_jwt_user = {"loaded_user": None}
#         return None
#
#     g._jwt_extended_jwt_user = _load_user(jwt_header, jwt_data)
#     g._jwt_extended_jwt_header = jwt_header
#     g._jwt_extended_jwt = jwt_data

def current_user_context_processor() -> Any:
    return {"current_user": get_current_user()}
