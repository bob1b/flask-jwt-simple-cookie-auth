import datetime
import jwt
from typing import (Any, Callable, Optional, TYPE_CHECKING)
from flask import Flask, current_app
from jwt import (DecodeError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError, InvalidTokenError,
                 MissingRequiredClaimError)

from . import user
from . import tokens
from . import exceptions
from . import default_callbacks
from .config import config
from .typing import (ExpiresDelta, Fresh)


def get_jwt_manager() -> "JWTManager":
    try:
        return current_app.extensions["flask-jwt-simple-cookie-auth"]
    except KeyError:  # pragma: no cover
        raise RuntimeError(
            "You must initialize a JWTManager with this flask application before using this method"
        ) from None


class JWTManager(object):
    """ An object used to hold JWT settings and callback functions for the Flask-JWT-Extended extension.

        Instances of :class:`JWTManager` are *not* bound to specific apps, so you can create one in the main body of
        your code and then bind it to your app in a factory function. """

    def __init__(self, app: Optional[Flask] = None, add_context_processor: bool = False) -> None:
        """ Create the JWTManager instance. You can either pass a flask application in directly here to register this
            extension with the flask app, or call init_app after creating this object (in a factory pattern).

            :param app:
                The Flask Application object
            :param add_context_processor:
                Controls if `current_user` should be added to flasks template context (and thus be available for use in
                Jinja templates). Defaults to ``False``. """
        # Register the default error handler callback methods. These can be
        # overridden with the appropriate loader decorators
        self.user_lookup_callback: Optional[Callable] = None
        self._decode_key_callback = default_callbacks.default_decode_key_callback
        self._encode_key_callback = default_callbacks.default_encode_key_callback
        self._unauthorized_callback = default_callbacks.default_unauthorized_callback
        self._expired_token_callback = default_callbacks.default_expired_token_callback
        self._invalid_token_callback = default_callbacks.default_invalid_token_callback
        self._revoked_token_callback = default_callbacks.default_revoked_token_callback
        self.token_in_blocklist_callback = default_callbacks.default_blocklist_callback
        self._user_identity_callback = default_callbacks.default_user_identity_callback
        self._user_claims_callback = default_callbacks.default_additional_claims_callback
        self._jwt_additional_header_callback = default_callbacks.default_jwt_headers_callback
        self._user_lookup_error_callback = default_callbacks.default_user_lookup_error_callback
        self._needs_fresh_token_callback = default_callbacks.default_needs_fresh_token_callback
        self.token_verification_callback = default_callbacks.default_token_verification_callback
        self._token_verification_failed_callback = default_callbacks.default_token_verification_failed_callback

        # Register this extension with the flask app now (if it is provided)
        if app is not None:
            self.init_app(app, add_context_processor)

    def init_app(self, app: Flask, add_context_processor: bool = False) -> None:
        """ Register this extension with the flask app.

            :param app:
                The Flask Application object
            :param add_context_processor:
                Controls if `current_user` should be added to flasks template context (and thus be available for use in
                Jinja templates). Defaults to ``False``. """
        # Save this so we can use it later in the extension
        if not hasattr(app, "extensions"):  # pragma: no cover
            app.extensions = {}
        app.extensions["flask-jwt-simple-cookie-auth"] = self

        if add_context_processor:
            app.context_processor(user.current_user_context_processor)

        # Set all the default configurations for this extension
        self._set_default_configuration_options(app)
        self._set_error_handler_callbacks(app)

    def _set_error_handler_callbacks(self, app: Flask) -> None:
        @app.errorhandler(exceptions.CSRFError)
        def handle_csrf_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(DecodeError)
        def handle_decode_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(ExpiredSignatureError)
        def handle_expired_error(e):
            return self._expired_token_callback(e.jwt_header, e.jwt_data)

        @app.errorhandler(exceptions.FreshTokenRequired)
        def handle_fresh_token_required(e):
            return self._needs_fresh_token_callback(e.jwt_header, e.jwt_data)

        @app.errorhandler(MissingRequiredClaimError)
        def handle_missing_required_claim_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidAudienceError)
        def handle_invalid_audience_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidIssuerError)
        def handle_invalid_issuer_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(InvalidTokenError)
        def handle_invalid_token_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(exceptions.JWTDecodeError)
        def handle_jwt_decode_error(e):
            return self._invalid_token_callback(str(e))

        @app.errorhandler(exceptions.NoAuthorizationError)
        def handle_auth_error(e):
            return self._unauthorized_callback(str(e))

        @app.errorhandler(exceptions.RevokedTokenError)
        def handle_revoked_token_error(e):
            return self._revoked_token_callback(e.jwt_header, e.jwt_data)

        @app.errorhandler(exceptions.UserClaimsVerificationError)
        def handle_failed_token_verification(e):
            return self._token_verification_failed_callback(e.jwt_header, e.jwt_data)

        @app.errorhandler(exceptions.UserLookupError)
        def handler_user_lookup_error(e):
            return self._user_lookup_error_callback(e.jwt_header, e.jwt_data)

        @app.errorhandler(exceptions.WrongTokenError)
        def handle_wrong_token_error(e):
            return self._invalid_token_callback(str(e))

    @staticmethod
    def _set_default_configuration_options(app: Flask) -> None:
        values =  [("JWT_ACCESS_TOKEN_EXPIRES", datetime.timedelta(minutes=15)),
                   ("JWT_ACCESS_COOKIE_NAME", "access_token_cookie"),
                   ("JWT_ACCESS_COOKIE_PATH", "/"),
                   ("JWT_ACCESS_CSRF_COOKIE_NAME", "csrf_access_token"),
                   ("JWT_ACCESS_CSRF_COOKIE_PATH", "/"),
                   ("JWT_ACCESS_CSRF_FIELD_NAME", "csrf_token"),
                   ("JWT_ACCESS_CSRF_HEADER_NAME", "X-CSRF-TOKEN"),
                   ("JWT_ALGORITHM", "HS256"),
                   ("JWT_COOKIE_CSRF_PROTECT", True),
                   ("JWT_COOKIE_DOMAIN", None),
                   ("JWT_COOKIE_SAMESITE", None),
                   ("JWT_COOKIE_SECURE", False),
                   ("JWT_CSRF_CHECK_FORM", False),
                   ("JWT_CSRF_IN_COOKIES", True),
                   ("JWT_CSRF_METHODS", ["POST", "PUT", "PATCH", "DELETE"]),
                   ("JWT_DECODE_ALGORITHMS", None),
                   ("JWT_DECODE_AUDIENCE", None),
                   ("JWT_DECODE_ISSUER", None),
                   ("JWT_DECODE_LEEWAY", 0),
                   ("JWT_ENCODE_AUDIENCE", None),
                   ("JWT_ENCODE_ISSUER", None),
                   ("JWT_ERROR_MESSAGE_KEY", "msg"),
                   ("JWT_IDENTITY_CLAIM", "sub"),
                   ("JWT_JSON_KEY", "access_token"),
                   ("JWT_PRIVATE_KEY", None),
                   ("JWT_PUBLIC_KEY", None),
                   ("JWT_QUERY_STRING_NAME", "jwt"),
                   ("JWT_QUERY_STRING_VALUE_PREFIX", ""),
                   ("JWT_REFRESH_COOKIE_NAME", "refresh_token_cookie"),
                   ("JWT_REFRESH_COOKIE_PATH", "/"),
                   ("JWT_REFRESH_CSRF_COOKIE_NAME", "csrf_refresh_token"),
                   ("JWT_REFRESH_CSRF_COOKIE_PATH", "/"),
                   ("JWT_REFRESH_CSRF_FIELD_NAME", "csrf_token"),
                   ("JWT_REFRESH_TOKEN_EXPIRES", datetime.timedelta(days=30)),
                   ("JWT_SECRET_KEY", None),
                   ("JWT_SESSION_COOKIE", True),
                   ("JWT_ENCODE_NBF", True)]
        for v in values:
            app.config.setdefault(v[0], v[1])

    def additional_claims_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to add additional claims when creating a JWT. The claims
            returned by this function will be merged with any claims passed in via the ``additional_claims`` argument to
            :func:`~flask_jwt_extended.create_access_token` or :func:`~flask_jwt_extended.create_refresh_token`.

            The decorated function must take **one** argument.
            The argument is the identity that was used when creating a JWT.
            The decorated function must return a dictionary of claims to add to the JWT.
        """
        self._user_claims_callback = callback
        return callback

    def additional_headers_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to add additional headers when creating a JWT. The headers
            returned by this function will be merged with any headers passed in via the ``additional_headers`` argument
            to :func:`~flask_jwt_extended.create_access_token` or :func:`~flask_jwt_extended.create_refresh_token`.

            The decorated function must take **one** argument.
            The argument is the identity that was used when creating a JWT.
            The decorated function must return a dictionary of headers to add to the JWT.
        """
        self._jwt_additional_header_callback = callback
        return callback

    def decode_key_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for dynamically setting the JWT decode key based on the
            **UNVERIFIED** contents of the token. Think carefully before using this functionality, in most cases you
            probably don't need it.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the unverified JWT.
            The second argument is a dictionary containing the payload data of the unverified JWT.
            The decorated function must return a *string* that is used to decode and verify the token.
        """
        self._decode_key_callback = callback
        return callback

    def encode_key_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for dynamically setting the JWT encode key based on the token's
            identity. Think carefully before using this functionality, in most cases you probably don't need it.

            The decorated function must take **one** argument.
            The argument is the identity used to create this JWT.
            The decorated function must return a *string* which is the secrete key used to encode the JWT.
        """
        self._encode_key_callback = callback
        return callback

    def expired_token_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for returning a custom response when an expired JWT is
            encountered.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return a Flask Response.
        """
        self._expired_token_callback = callback
        return callback

    def invalid_token_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for returning a custom response when an invalid JWT is
            encountered.

            This decorator sets the callback function that will be used if an invalid JWT attempts to access a protected
            endpoint.

            The decorated function must take **one** argument.
            The argument is a string which contains the reason why a token is invalid.
            The decorated function must return a Flask Response.
        """
        self._invalid_token_callback = callback
        return callback

    def needs_fresh_token_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for returning a custom response when a valid and non-fresh token
            is used on an endpoint that is marked as ``fresh=True``.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return a Flask Response.
        """
        self._needs_fresh_token_callback = callback
        return callback

    def revoked_token_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function for returning a custom response when a revoked token is
            encountered.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return a Flask Response.
        """
        self._revoked_token_callback = callback
        return callback

    def token_in_blocklist_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to check if a JWT has been revoked.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must be return ``True`` if the token has been revoked, ``False`` otherwise.
        """
        self.token_in_blocklist_callback = callback
        return callback

    def token_verification_failed_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to return a custom response when the claims verification
            check fails.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return a Flask Response.
        """
        self._token_verification_failed_callback = callback
        return callback

    def token_verification_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used for custom verification of a valid JWT.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return ``True`` if the token is valid, or ``False`` otherwise.
        """
        self.token_verification_callback = callback
        return callback

    def unauthorized_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to return a custom response when no JWT is present.

            The decorated function must take **one** argument.
            The argument is a string that explains why the JWT could not be found.
            The decorated function must return a Flask Response.
        """
        self._unauthorized_callback = callback
        return callback

    def user_identity_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to convert an identity to a JSON serializable format when
            creating JWTs. This is useful for using objects (such as SQLAlchemy instances) as the identity when
            creating your tokens.

            The decorated function must take **one** argument.
            The argument is the identity that was used when creating a JWT.
            The decorated function must return JSON serializable data.
        """
        self._user_identity_callback = callback
        return callback

    def user_lookup_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to convert a JWT into a python object that can be used in a
            protected endpoint. This is useful for automatically loading a SQLAlchemy instance based on the contents
            of the JWT.

            The object returned from this function can be accessed via :attr:`~flask_jwt_extended.current_user` or
            :meth:`~flask_jwt_extended.get_current_user`

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function can return any python object, which can then be accessed in a protected endpoint.
                If an object cannot be loaded, for example if a user has been deleted from your database, ``None`` must
                be returned to indicate that an error occurred loading the user.
        """
        self.user_lookup_callback = callback
        return callback

    def user_lookup_error_loader(self, callback: Callable) -> Callable:
        """
            This decorator sets the callback function used to return a custom response when loading a user via
            :meth:`~flask_jwt_extended.JWTManager.user_lookup_loader` fails.

            The decorated function must take **two** arguments.
            The first argument is a dictionary containing the header data of the JWT.
            The second argument is a dictionary containing the payload data of the JWT.
            The decorated function must return a Flask Response.
        """
        self._user_lookup_error_callback = callback
        return callback

    def encode_jwt_from_config(self, identity: Any, token_type: str, claims=None, fresh: Fresh = False,
                               expires_delta: Optional[ExpiresDelta] = None, headers=None) -> str:
        header_overrides = self._jwt_additional_header_callback(identity)
        if headers is not None:
            header_overrides.update(headers)

        claim_overrides = self._user_claims_callback(identity)
        if claims is not None:
            claim_overrides.update(claims)

        if expires_delta is None:
            if token_type == "access":
                expires_delta = config.access_expires
            else:
                expires_delta = config.refresh_expires

        return tokens._encode_jwt(
            algorithm=config.algorithm,
            audience=config.encode_audience,
            claim_overrides=claim_overrides,
            csrf=config.csrf_protect,
            expires_delta=expires_delta,
            fresh=fresh,
            header_overrides=header_overrides,
            identity=self._user_identity_callback(identity),
            identity_claim_key=config.identity_claim_key,
            issuer=config.encode_issuer,
            json_encoder=config.json_encoder,
            secret=self._encode_key_callback(identity),
            token_type=token_type,
            nbf=config.encode_nbf,
        )

    def decode_jwt_from_config(self, encoded_token: str, csrf_value=None, allow_expired: bool = False) -> dict:
        unverified_claims = jwt.decode(
            encoded_token,
            algorithms=config.decode_algorithms,
            options={"verify_signature": False},
        )
        unverified_headers = jwt.get_unverified_header(encoded_token)
        secret = self._decode_key_callback(unverified_headers, unverified_claims)

        kwargs = {
            "algorithms": config.decode_algorithms,
            "audience": config.decode_audience,
            "csrf_value": csrf_value,
            "encoded_token": encoded_token,
            "identity_claim_key": config.identity_claim_key,
            "issuer": config.decode_issuer,
            "leeway": config.leeway,
            "secret": secret,
            "verify_aud": config.decode_audience is not None,
        }

        try:
            return tokens._decode_jwt(**kwargs, allow_expired=allow_expired)
        except ExpiredSignatureError as e:
            # TODO: If we ever do another breaking change, don't raise this pyjwt error directly, instead raise a custom
            #  error of ours from this error.
            e.jwt_header = unverified_headers  # type: ignore
            e.jwt_data = tokens._decode_jwt(**kwargs, allow_expired=True)  # type: ignore
            if not allow_expired:
                raise
