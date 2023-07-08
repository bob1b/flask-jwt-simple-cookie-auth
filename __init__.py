from .jwt_manager import JWTManager as JWTManager
from .utils import (create_access_token, create_refresh_token, current_user, decode_token, get_csrf_token,
                    get_current_user, get_jti, get_jwt, get_jwt_header, get_jwt_identity, get_jwt_request_location,
                    get_unverified_jwt_headers, set_access_cookies, set_refresh_cookies, unset_access_cookies,
                    unset_jwt_cookies, unset_refresh_cookies, get_access_cookie_value, get_refresh_cookie_value)
from .view_decorators import (jwt_required, verify_jwt_in_request)

__version__ = "4.5.2" # modified by bob1b
