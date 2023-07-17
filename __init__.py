from .user import *
from .utils import *
from .tokens import *
from .config import *
from .exceptions import *
from .view_decorators import *
from .default_callbacks import *
from .jwt_manager import JWTManager

__version__ = "b4.5.2"  # modified by bob1b


## features ##
# TODO - is a user logged in or not? return user_id or None
# TODO - JWT parsing utils
# TODO - token creation utils
# TODO - log in / log out
# TODO - token expiration config
# .. what else?


"""
  Files:
    * config.py - config handling for JWT, mainly @property methods
    * default_callbacks.py - callbacks for things like user_identity_loader and user_lookup_loader
    * exceptions.py - exception classes, some containing __init__ code
    * internal_utils.py - small set of utils used by package but supposedly not available outside it
    * jwt_manager.py - JWTManager class: initialization, set error handler callbacks, set default config param values,
                       additional loaders for token statuses, user identity loader, encode_jwt_from_config(),
                       _decode_jwt_from_config()
    * py.typed - empty
    * tokens.py - _encode_jwt(), _decode_jwt(), my method: refresh_expiring_jwts(), my method: after_request()
    * typing.py - type hints setup
    * user.py (mine) - user-specific methods: login, logout, remove_expired_tokens, create_access_token,
                                              create_refresh_token
    * utils.py - get_jwt(), get_jwt_header(), get_jwt_identity(), get_current_user(), decode_token(),
                 maybe my method: set_current_user_from_token_string(), create_access_token() same as in user.py?,
                 create_refresh_token() same as in user.py?, get_unverified_jwt_headers(), get_jti(), get_csrf_token(),
                 set_access_cookies(), my get_access_cookie_value(), set_refresh_cookies(), my get_refresh_cookie_value(),
                 unset_jwt_cookies(), unset_access_cookies(), unset_refresh_cookies(), current_user_context_processor() ??
    * view_decorators.py - jwt_sca() and supporting util methods. This decorator will likely need to be adjusted

    What exactly is a claim: an unverified statement of identity?
        It's a potentially unvalidated part of the JWT token, e.g "sub" (user identity)

"""
