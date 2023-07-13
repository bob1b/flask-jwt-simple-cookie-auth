from .jwt_manager import JWTManager as JWTManager
from .utils import (create_access_token, create_refresh_token, current_user, decode_token, get_csrf_token,
                    get_current_user, get_jti, get_jwt, get_jwt_header, get_jwt_identity, get_unverified_jwt_headers,
                    set_access_cookies, set_refresh_cookies, unset_access_cookies, unset_jwt_cookies,
                    unset_refresh_cookies, get_access_cookie_value, get_refresh_cookie_value)
from .view_decorators import (jwt_required, verify_jwt_in_request)

__version__ = "b4.5.2"  # modified by bob1b

# TODO - is a user logged in or not? return user_id or None
# TODO - JWT parsing utils
# TODO - token creation utils
# TODO - auto token refreshing before request is processed
# TODO - log in / log out
# TODO - token expiration config