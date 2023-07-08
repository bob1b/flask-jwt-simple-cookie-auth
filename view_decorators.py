from datetime import (datetime, timezone)
from functools import wraps
from re import split
from typing import (Any, Optional, Sequence, Tuple, Union)

from flask import (current_app, g, request)
from werkzeug.exceptions import BadRequest

from .config import config
from jwt import ExpiredSignatureError
from .exceptions import (CSRFError, FreshTokenRequired, InvalidHeaderError, InvalidQueryParamError,
                         NoAuthorizationError, UserLookupError)
from .internal_utils import (custom_verification_for_token, has_user_lookup, user_lookup, verify_token_not_blocklisted,
                             verify_token_type)
from .utils import (decode_token, get_unverified_jwt_headers)

LocationType = Union[str, Sequence, None]


def _verify_token_is_fresh(jwt_header: dict, jwt_data: dict) -> None:
    fresh = jwt_data["fresh"]
    if isinstance(fresh, bool):
        if not fresh:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)
    else:
        now = datetime.timestamp(datetime.now(timezone.utc))
        if fresh < now:
            raise FreshTokenRequired("Fresh token required", jwt_header, jwt_data)


def verify_jwt_in_request(
    optional: bool = False,
    no_exception_on_expired: bool = False,
    fresh: bool = False,
    refresh: bool = False,
    locations: Optional[LocationType] = None,
    verify_type: bool = True,
    skip_revocation_check: bool = False,
) -> Optional[Tuple[dict, dict]]:
    """
    Verify that a valid JWT is present in the request, unless ``optional=True`` in
    which case no JWT is also considered valid.

    :param optional:
        If ``True``, do not raise an error if no JWT is present in the request.
        Defaults to ``False``.

    :param no_exception_on_expired:
        If ``True``, do not raise an error if no JWT is expired.
        Defaults to ``False``.

    :param fresh:
        If ``True``, require a JWT marked as ``fresh`` in order to be verified.
        Defaults to ``False``.

    :param refresh:
        If ``True``, requires a refresh JWT to access this endpoint. If ``False``,
        requires an access JWT to access this endpoint. Defaults to ``False``

    :param locations:
        A location or list of locations to look for the JWT in this request, for
        example ``'headers'`` or ``['headers', 'cookies']``. Defaults to ``None``
        which indicates that JWTs will be looked for in the locations defined by the
        ``JWT_TOKEN_LOCATION`` configuration option.

    :param verify_type:
        If ``True``, the token type (access or refresh) will be checked according
        to the ``refresh`` argument. If ``False``, type will not be checked and both
        access and refresh tokens will be accepted.

    :param skip_revocation_check:
        If ``True``, revocation status of the token will be *not* checked. If ``False``,
        revocation status of the token will be checked.

    :param skip_revocation_check:
        If ``True``, revocation status of the token will be *not* checked. If ``False``,
        revocation status of the token will be checked.

    :return:
        A tuple containing the jwt_header and the jwt_data if a valid JWT is
        present in the request. If ``optional=True`` and no JWT is in the request,
        ``None`` will be returned instead. Raise an exception if an invalid JWT
        is in the request.
    """
    if request.method in config.exempt_methods:
        return None

    try:
        jwt_data, jwt_header, jwt_location = _decode_jwt_from_request(
            locations,
            fresh,
            refresh=refresh,
            verify_type=verify_type,
            skip_revocation_check=skip_revocation_check,
        )

    except (NoAuthorizationError, ExpiredSignatureError) as e:
        if type(e) == NoAuthorizationError and not optional:
            raise
        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            raise
        g._jwt_extended_jwt = {}
        g._jwt_extended_jwt_header = {}
        g._jwt_extended_jwt_user = {"loaded_user": None}
        g._jwt_extended_jwt_location = None
        return None

    # Save these at the very end so that they are only saved in the request
    # context if the token is valid and all callbacks succeed
    g._jwt_extended_jwt_user = _load_user(jwt_header, jwt_data)
    g._jwt_extended_jwt_header = jwt_header
    g._jwt_extended_jwt = jwt_data
    g._jwt_extended_jwt_location = jwt_location

    return jwt_header, jwt_data


def jwt_required(
    optional: bool = False,
    fresh: bool = False,
    refresh: bool = False,
    locations: Optional[LocationType] = None,
    verify_type: bool = True,
    skip_revocation_check: bool = False,
) -> Any:
    """
    A decorator to protect a Flask endpoint with JSON Web Tokens.

    Any route decorated with this will require a valid JWT to be present in the
    request (unless optional=True, in which case no JWT is also valid) before the
    endpoint can be called.

    :param optional:
        If ``True``, allow the decorated endpoint to be accessed if no JWT is present in
        the request. Defaults to ``False``.

    :param fresh:
        If ``True``, require a JWT marked with ``fresh`` to be able to access this
        endpoint. Defaults to ``False``.

    :param refresh:
        If ``True``, requires a refresh JWT to access this endpoint. If ``False``,
        requires an access JWT to access this endpoint. Defaults to ``False``.

    :param locations:
        A location or list of locations to look for the JWT in this request, for
        example ``'headers'`` or ``['headers', 'cookies']``. Defaults to ``None``
        which indicates that JWTs will be looked for in the locations defined by the
        ``JWT_TOKEN_LOCATION`` configuration option.

    :param verify_type:
        If ``True``, the token type (access or refresh) will be checked according
        to the ``refresh`` argument. If ``False``, type will not be checked and both
        access and refresh tokens will be accepted.

    :param skip_revocation_check:
        If ``True``, revocation status of the token will be *not* checked. If ``False``,
        revocation status of the token will be checked.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request(
                optional, fresh, refresh, locations, verify_type, skip_revocation_check
            )
            return current_app.ensure_sync(fn)(*args, **kwargs)

        return decorator

    return wrapper


def _load_user(jwt_header: dict, jwt_data: dict) -> Optional[dict]:
    if not has_user_lookup():
        return None

    identity = jwt_data[config.identity_claim_key]
    user = user_lookup(jwt_header, jwt_data)
    if user is None:
        error_msg = "user_lookup returned None for {}".format(identity)
        raise UserLookupError(error_msg, jwt_header, jwt_data)
    return {"loaded_user": user}


def _decode_jwt_from_headers() -> Tuple[str, None]:
    header_name = config.header_name
    header_type = config.header_type

    # Verify we have the auth header
    auth_header = request.headers.get(header_name, "").strip().strip(",")
    if not auth_header:
        raise NoAuthorizationError(f"Missing {header_name} Header")

    # Make sure the header is in a valid format that we are expecting, ie
    # <HeaderName>: <HeaderType(optional)> <JWT>.
    #
    # Also handle the fact that the header that can be comma delimited, ie
    # <HeaderName>: <field> <value>, <field> <value>, etc...
    if header_type:
        field_values = split(r",\s*", auth_header)
        jwt_headers = [s for s in field_values if s.split()[0] == header_type]
        if len(jwt_headers) != 1:
            msg = (
                f"Missing '{header_type}' type in '{header_name}' header. "
                f"Expected '{header_name}: {header_type} <JWT>'"
            )
            raise NoAuthorizationError(msg)

        parts = jwt_headers[0].split()
        if len(parts) != 2:
            msg = (
                f"Bad {header_name} header. "
                f"Expected '{header_name}: {header_type} <JWT>'"
            )
            raise InvalidHeaderError(msg)

        encoded_token = parts[1]
    else:
        parts = auth_header.split()
        if len(parts) != 1:
            msg = f"Bad {header_name} header. Expected '{header_name}: <JWT>'"
            raise InvalidHeaderError(msg)

        encoded_token = parts[0]

    return encoded_token, None


def _decode_jwt_from_cookies(refresh: bool) -> Tuple[str, Optional[str]]:
    if refresh:
        cookie_key = config.refresh_cookie_name
        csrf_header_key = config.refresh_csrf_header_name
        csrf_field_key = config.refresh_csrf_field_name
    else:
        cookie_key = config.access_cookie_name
        csrf_header_key = config.access_csrf_header_name
        csrf_field_key = config.access_csrf_field_name

    encoded_token = request.cookies.get(cookie_key)
    if not encoded_token:
        raise NoAuthorizationError('Missing cookie "{}"'.format(cookie_key))

    if config.csrf_protect and request.method in config.csrf_request_methods:
        if config.csrf_in_cookies:
            csrf_value = request.cookies.get(config.access_csrf_cookie_name)
        else:
            csrf_value = request.headers.get(csrf_header_key, None)
        if not csrf_value and config.csrf_check_form:
            csrf_value = request.form.get(csrf_field_key, None)
        if not csrf_value:
            raise CSRFError("Missing CSRF token")
    else:
        csrf_value = None

    return encoded_token, csrf_value


def _decode_jwt_from_query_string() -> Tuple[str, None]:
    param_name = config.query_string_name
    prefix = config.query_string_value_prefix

    value = request.args.get(param_name)
    if not value:
        raise NoAuthorizationError(f"Missing '{param_name}' query paramater")

    if not value.startswith(prefix):
        raise InvalidQueryParamError(
            f"Invalid value for query parameter '{param_name}'. "
            f"Expected the value to start with '{prefix}'"
        )

    encoded_token = value[len(prefix) :]  # noqa: E203
    return encoded_token, None


def _decode_jwt_from_json(refresh: bool) -> Tuple[str, None]:
    if not request.is_json:
        raise NoAuthorizationError("Invalid content-type. Must be application/json.")

    if refresh:
        token_key = config.refresh_json_key
    else:
        token_key = config.json_key

    try:
        encoded_token = request.json and request.json.get(token_key, None)
        if not encoded_token:
            raise BadRequest()
    except BadRequest:
        raise NoAuthorizationError(
            'Missing "{}" key in json data.'.format(token_key)
        ) from None

    return encoded_token, None


def _decode_jwt_from_request(
    locations: LocationType,
    fresh: bool,
    refresh: bool = False,
    verify_type: bool = True,
    skip_revocation_check: bool = False,
) -> Tuple[dict, dict, str]:
    # Figure out what locations to look for the JWT in this request
    if isinstance(locations, str):
        locations = [locations]

    if not locations:
        locations = config.token_location

    # Get the decode functions in the order specified by locations.
    # Each entry in this list is a tuple (<location>, <encoded-token-function>)
    get_encoded_token_functions = []
    for location in locations:
        if location == "cookies":
            get_encoded_token_functions.append(
                (location, lambda: _decode_jwt_from_cookies(refresh))
            )
        elif location == "query_string":
            get_encoded_token_functions.append(
                (location, _decode_jwt_from_query_string)
            )
        elif location == "headers":
            get_encoded_token_functions.append((location, _decode_jwt_from_headers))
        elif location == "json":
            get_encoded_token_functions.append(
                (location, lambda: _decode_jwt_from_json(refresh))
            )
        else:
            raise RuntimeError(f"'{location}' is not a valid location")

    # Try to find the token from one of these locations. It only needs to exist
    # in one place to be valid (not every location).
    errors = []
    decoded_token = None
    for location, get_encoded_token_function in get_encoded_token_functions:
        try:
            encoded_token, csrf_token = get_encoded_token_function()
            decoded_token = decode_token(encoded_token, csrf_token)
            jwt_location = location
            jwt_header = get_unverified_jwt_headers(encoded_token)
            break
        except NoAuthorizationError as e:
            errors.append(str(e))

    # Do some work to make a helpful and human-readable error message if no
    # token was found in any of the expected locations.
    if not decoded_token:
        if len(locations) > 1:
            err_msg = "Missing JWT in {start_locs} or {end_locs} ({details})".format(
                start_locs=", ".join(locations[:-1]),
                end_locs=locations[-1],
                details="; ".join(errors),
            )
            raise NoAuthorizationError(err_msg)
        else:
            raise NoAuthorizationError(errors[0])

    # Additional verifications provided by this extension
    if verify_type:
        verify_token_type(decoded_token, refresh)

    if fresh:
        _verify_token_is_fresh(jwt_header, decoded_token)

    if not skip_revocation_check:
        verify_token_not_blocklisted(jwt_header, decoded_token)

    custom_verification_for_token(jwt_header, decoded_token)

    return decoded_token, jwt_header, jwt_location
