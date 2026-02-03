import logging
import datetime
from flask import current_app
from jwt.algorithms import requires_cryptography
from typing import (Iterable, List, Optional, Union)
from .types import ExpiresDelta

_logger = logging.getLogger(__name__)


class _Config:
    """
        Helper object for accessing and verifying options in this extension. This is meant for internal use of the
        application; modifying config options should be done with flasks ```app.config```.

        Default values for the configuration options are set in the jwt_manager object. All of these values are read-only.
        This is simply a loose wrapper with some helper functionality for flasks `app.config`.
    """

    @property
    def is_asymmetric(self) -> bool:
        return self.algorithm in requires_cryptography

    @property
    def encode_key(self) -> str:
        return self._private_key if self.is_asymmetric else self._secret_key

    @property
    def decode_key(self) -> str:
        return self._public_key if self.is_asymmetric else self._secret_key

    @property
    def query_string_name(self) -> str:
        return current_app.config["JWT_QUERY_STRING_NAME"]

    @property
    def query_string_value_prefix(self) -> str:
        return current_app.config["JWT_QUERY_STRING_VALUE_PREFIX"]

    @property
    def access_cookie_name(self) -> str:
        return current_app.config["JWT_ACCESS_COOKIE_NAME"]

    @property
    def refresh_cookie_name(self) -> str:
        return current_app.config["JWT_REFRESH_COOKIE_NAME"]

    @property
    def access_cookie_path(self) -> str:
        return current_app.config["JWT_ACCESS_COOKIE_PATH"]

    @property
    def refresh_cookie_path(self) -> str:
        return current_app.config["JWT_REFRESH_COOKIE_PATH"]

    @property
    def cookie_secure(self) -> bool:
        return current_app.config["JWT_COOKIE_SECURE"]

    @property
    def cookie_domain(self) -> str:
        return current_app.config["JWT_COOKIE_DOMAIN"]

    @property
    def session_cookie(self) -> bool:
        return current_app.config["JWT_SESSION_COOKIE"]

    @property
    def cookie_samesite(self) -> str:
        return current_app.config["JWT_COOKIE_SAMESITE"]

    @property
    def csrf_protect(self) -> bool:
        return current_app.config["JWT_COOKIE_CSRF_PROTECT"]

    @property
    def csrf_request_methods(self) -> Iterable[str]:
        return current_app.config["JWT_CSRF_METHODS"]

    @property
    def access_csrf_cookie_name(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_COOKIE_NAME"]

    @property
    def refresh_csrf_cookie_name(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_COOKIE_NAME"]

    @property
    def access_csrf_cookie_path(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_COOKIE_PATH"]

    @property
    def refresh_csrf_cookie_path(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_COOKIE_PATH"]

    @property
    def csrf_check_form(self) -> bool:
        return current_app.config["JWT_CSRF_CHECK_FORM"]

    @property
    def access_csrf_field_name(self) -> str:
        return current_app.config["JWT_ACCESS_CSRF_FIELD_NAME"]

    @property
    def refresh_csrf_field_name(self) -> str:
        return current_app.config["JWT_REFRESH_CSRF_FIELD_NAME"]

    @property
    def access_expires(self) -> ExpiresDelta:
        delta = current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
        if isinstance(delta, int):
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            try:
                # Basically runtime typechecking. Probably a better way to do this with proper type checking
                delta + datetime.datetime.now(datetime.UTC)
            except TypeError as e:
                err = "must be able to add JWT_ACCESS_TOKEN_EXPIRES to datetime.datetime"
                _logger.error(err)
                raise RuntimeError(err) from e
        return delta

    @property
    def refresh_expires(self) -> ExpiresDelta:
        delta = current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
        if isinstance(delta, int):
            delta = datetime.timedelta(seconds=delta)
        if delta is not False:
            # Basically runtime typechecking. Probably a better way to do this with proper type checking
            try:
                delta + datetime.datetime.now(datetime.UTC)
            except TypeError as e:
                err = "must be able to add JWT_REFRESH_TOKEN_EXPIRES to datetime.datetime"
                _logger.error(err)
                raise RuntimeError(err) from e
        return delta

    @property
    def access_refresh_after_percent_expired(self) -> float:
        """ access tokens will begin refreshing when they are this percent expired """
        return current_app.config.get("JWT_ACCESS_TOKEN_REFRESH_AFTER_PERCENT_EXPIRED", 60)

    @property
    def algorithm(self) -> str:
        return current_app.config["JWT_ALGORITHM"]

    @property
    def decode_algorithms(self) -> List[str]:
        algorithms = current_app.config["JWT_DECODE_ALGORITHMS"]
        if not algorithms:
            return [self.algorithm]
        if self.algorithm not in algorithms:
            algorithms.append(self.algorithm)
        return algorithms

    @property
    def _secret_key(self) -> str:
        key = current_app.config["JWT_SECRET_KEY"]
        if not key:
            key = current_app.config.get("SECRET_KEY", None)
            if not key:
                err = f"JWT_SECRET_KEY or flask SECRET_KEY must be set when using symmetric algorithm " + \
                      f"'{self.algorithm}'"
                raise RuntimeError(err)
        return key

    @property
    def _public_key(self) -> str:
        key = current_app.config["JWT_PUBLIC_KEY"]
        if not key:
            err = f"JWT_PUBLIC_KEY must be set to use asymmetric cryptography algorithm '{self.algorithm}'"
            _logger.error(err)
            raise RuntimeError(err)
        return key

    @property
    def _private_key(self) -> str:
        key = current_app.config["JWT_PRIVATE_KEY"]
        if not key:
            err = f"JWT_PRIVATE_KEY must be set to use asymmetric cryptography algorithm '{self.algorithm}'"
            _logger.error(err)
            raise RuntimeError(err)
        return key

    @property
    def cookie_max_age(self) -> Optional[int]:
        # Returns the appropriate value for max_age for flask set_cookies. If the session cookie is true, return None,
        # otherwise return the number of seconds in 1 year
        return None if self.session_cookie else 31540000

    @property
    def identity_claim_key(self) -> str:
        return current_app.config["JWT_IDENTITY_CLAIM"]

    @property
    def exempt_methods(self) -> Iterable[str]:
        return {"OPTIONS"}

    @property
    def error_msg_key(self) -> str:
        return current_app.config["JWT_ERROR_MESSAGE_KEY"]

    @property
    def decode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config["JWT_DECODE_AUDIENCE"]

    @property
    def encode_audience(self) -> Union[str, Iterable[str]]:
        return current_app.config["JWT_ENCODE_AUDIENCE"]

    @property
    def encode_issuer(self) -> str:
        return current_app.config["JWT_ENCODE_ISSUER"]

    @property
    def decode_issuer(self) -> str:
        return current_app.config["JWT_DECODE_ISSUER"]

    @property
    def leeway(self) -> int:
        return current_app.config["JWT_DECODE_LEEWAY"]

    @property
    def encode_nbf(self) -> bool:
        return current_app.config["JWT_ENCODE_NBF"]

    @property
    def clear_g_after_decorated_request(self) -> bool:
        return current_app.config["JWT_CLEAR_G_AFTER_DECORATED_REQUEST"]

config = _Config()
