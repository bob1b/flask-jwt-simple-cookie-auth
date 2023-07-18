import json
from typing import (Any, Type)
from flask import (current_app, Flask)

try:
    from flask.json.provider import DefaultJSONProvider

    HAS_JSON_PROVIDER = True
except ModuleNotFoundError:  # pragma: no cover
    # The flask.json.provider module was added in Flask 2.2.
    # Further details are handled in get_json_encoder.
    HAS_JSON_PROVIDER = False


class JSONEncoder(json.JSONEncoder):
    """A JSON encoder which uses the app.json_provider_class for the default"""

    def default(self, o: Any) -> Any:
        # If the registered JSON provider does not implement a default class method use the method defined by the
        # DefaultJSONProvider
        default = getattr(current_app.json_provider_class, "default", DefaultJSONProvider.default)
        return default(o)


def get_json_encoder(app: Flask) -> Type[json.JSONEncoder]:
    """Get the JSON Encoder for the provided flask app

    Starting with flask version 2.2 the flask application provides an interface to register a custom JSON
    Encoder/Decoder under the json_provider_class.

    As this interface is not compatible with the standard JSONEncoder, the `default` method of the class is wrapped.

    Lookup Order:
      - app.json_encoder - For Flask < 2.2
      - app.json_provider_class.default
      - flask.json.provider.DefaultJSONProvider.default

    """
    if not HAS_JSON_PROVIDER:  # pragma: no cover
        return app.json_encoder  # type: ignore

    return JSONEncoder
