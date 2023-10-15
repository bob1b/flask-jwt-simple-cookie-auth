import jwt
import logging
import traceback

from flask import request
from sqlalchemy import and_
from datetime import datetime
from jwt import ExpiredSignatureError
from typing import (Any, Optional, Tuple)

from . import utils
from . import jwt_user
from . import jwt_manager
from . import jwt_exceptions

from . import tokens_utils
from . import tokens_cookies
from . import tokens_validation

from .config import config


_logger = logging.getLogger(__name__)


def process_and_handle_tokens(fresh: bool = False,
                              optional: bool = False,
                              verify_type: bool = True,
                              auto_refresh: bool = True,
                              skip_revocation_check: bool = False,
                              no_exception_on_expired: bool = False) -> Optional[dict]:
    """
        Handles token validation and auto-refreshing (if enabled by auto_refresh). Catches exceptions raised by token
        validation based on method parameters

        :param auto_refresh:
            If ``True``, refresh expired tokens automatically and continue without exception

        :param optional:
            If ``True``, do not raise an error if no JWT is present in the request. Defaults to ``False``.

        :param no_exception_on_expired:
            If ``True``, do not raise an error if a JWT has expired. Defaults to ``False``.

        :param fresh:
            If ``True``, require a JWT marked as ``fresh`` in order to be verified. Defaults to ``False``.

        :param verify_type:
            If ``True``, the token type (access or refresh) will be checked according to the ``refresh`` argument. If
            ``False``, type will not be checked and both access and refresh tokens will be accepted.

        :param skip_revocation_check:
            If ``True``, revocation status of the token will *not* be checked. If ``False``, revocation status of the
            token will be checked.

        :return:
            If a valid JWT (or an expired but refreshable JWT) was provided in the request cookies:
               Returns a dict containing the decoded token data
            If no JWT was supplied in the cookies, or if the JWT is invalid or expired:
               Returns ``None``
            If ``optional=False``, raise an exception if an invalid JWT was supplied

        # algorithm flow looks something like:

           process_and_handle_tokens()
               -> jwt.get_unverified_header()

               -> decode_and_validate_tokens()
                    -> token_validation()
                        -> decode_token()
                            -> jwt.decode()
                        -> verify_token_not_blocklisted()
                            -> find_token_object_by_string()
                        -> get_jwt_identity()

                    -> tokens_refresh.refresh_expiring_jwts()
                        # if refreshing the token, the same validation as above is rerun
                        -> token_validation()
                            -> decode_token()
                                -> jwt.decode()
                            -> verify_token_not_blocklisted()
                                -> find_token_object_by_string()
                            -> get_jwt_identity()

                        -> jwt_user.set_no_user()

               -> jwt_user.set_no_user  OR  jwt_user.set_current_user()

    """
    method = f'tokens.process_and_handle_tokens()'
    if request.method in config.exempt_methods:
        return None

    try:
        # Check if the request even has cookies. get_tokens_from_cookies() checks "flask.g" and will use the refreshed
        # access token if there is one
        enc_access_token, enc_refresh_token, csrf_tokens = tokens_cookies.get_tokens_from_cookies()
        if not enc_access_token or not enc_refresh_token: # TODO - csrf
            return None

        jwt_header = jwt.get_unverified_header(enc_access_token) # example jwt_header:  {"alg": "HS256", "typ": "JWT"}

        opt = {
            "fresh": fresh,
            "leeway": config.leeway,
            "jwt_header": jwt_header,  # unverified headers
            "csrf_tokens": csrf_tokens,
            "verify_type": verify_type,
            "issuer": config.decode_issuer,
            "audience": config.decode_audience,
            "enc_access_token": enc_access_token,
            "enc_refresh_token": enc_refresh_token,
            "algorithms": config.decode_algorithms,
            "skip_revocation_check": skip_revocation_check,
            "identity_claim_key": config.identity_claim_key,
            "verify_aud": config.decode_audience is not None,
            "no_exception_on_expired": no_exception_on_expired,
            "auto_refresh": auto_refresh if auto_refresh is not None else False,
            "validate_csrf_for_this_request": config.csrf_protect and request.method in config.csrf_request_methods
        }

        # decode_and_validate_tokens() - if the user is using an expired access token, this method will attempt to
        #                                refresh it using refresh_expiring_jwts(). If the token expired and cannot be
        #                                refreshed, then returns None
        _logger.info(f'{method}: before decode_and_validate_tokens, {tokens_utils.displayable_from_encoded_token(opt["enc_access_token"])}')
        dec_access_token, dec_refresh_token = tokens_validation.decode_and_validate_tokens(opt)
        _logger.info(f'{method}: after decode_and_validate_tokens, {tokens_utils.displayable_from_decoded_token(dec_access_token)}')

    # all exceptions relating to bad tokens should be caught here so that set_no_user() can be called
    except (jwt_exceptions.NoAuthorizationError, ExpiredSignatureError, jwt_exceptions.RevokedTokenError) as e:

        if type(e) == jwt_exceptions.NoAuthorizationError and not optional:
            _logger.error(f'{method}: {type(e)}: {e}')
            raise

        if type(e) == ExpiredSignatureError and not no_exception_on_expired:
            _logger.error(f'{method}: {type(e)}: {e}')
            raise

        # TODO - the problem is that when a token is refreshed, the following exception is still triggered
        #   ERROR - tokens.process_and_handle_tokens(): got exception Access token has expired 12 seconds ago - setting no-user
        _logger.error(f'{method}: got exception {type(e)}: {e} - setting no-user')
        jwt_user.set_no_user()
        return None

    except Exception as e:
        _logger.error(f'{method}: exception: {e}, {traceback.format_exc()}')
        return None

    # Save these at the very end so that they are only saved in the request context if the token is valid and all
    # callbacks succeed
    # jwt_header = jwt.get_unverified_header(enc_access_token)
    _logger.info(f"{method}: calling set_current_user(): {tokens_utils.displayable_from_decoded_token(dec_access_token)}")
    jwt_user.set_current_user(jwt_header, dec_access_token)

    return dec_access_token


def find_token_object_by_string(
        encrypted_token: str,
        token_class: Any,
        user_id: Optional[int]=None,
        session: Optional[object]=None, # TODO - might need to use this to lock the row correctly
        lock_if_found: Optional[bool]=False,
) -> Optional[object]:
    """
        Attempts to find the encrypted token string in the token table associated with `token_class`

        returns: the matching token or None
    """
    method = f'find_token_object_by_string({token_class}, {utils.shorten_middle(encrypted_token, 20)}, ' + \
             f'user_id={user_id})'

    if session:
        token_query = session.query(token_class)
    else:
        token_query = token_class.query

    token_query = token_query.filter_by(token=encrypted_token)
    if user_id:
        token_query = token_query.filter_by(user_id=user_id)

    # fetch all results and warn if we get more than one. Then return 0 or 1 result anyway
    query_result = token_query.all()
    if len(query_result) > 1:
        _logger.warning(f'{method}: search for token yielded {len(query_result)} results, when there should only be ' +
                        'one in the table. Returning the first result')

    if len(query_result) < 1:
        return None
    return query_result[0]
