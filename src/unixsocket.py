import email.message
import email.parser
import http.client
import json
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import (
    Any,
    Dict,
    Generator,
    Literal,
    Optional,
    Union,
)


class SocketClient:
    """
    Defaults to using a Unix socket at socket_path (which must be specified
    unless a custom opener is provided).

    Originally copy-pasted from ops.pebble.Client.
    """

    def __init__(self, socket_path: str,
                 opener: Optional[urllib.request.OpenerDirector] = None,
                 base_url: str = 'http://localhost',
                 timeout: float = 5.0):
        if not isinstance(socket_path, str):
            raise TypeError(f'`socket_path` should be a string, not: {type(socket_path)}')
        if opener is None:
            opener = self._get_default_opener(socket_path)
        self.socket_path = socket_path
        self.opener = opener
        self.base_url = base_url
        self.timeout = timeout

    @classmethod
    def _get_default_opener(cls, socket_path: str) -> urllib.request.OpenerDirector:
        """Build the default opener to use for requests (HTTP over Unix socket)."""
        opener = urllib.request.OpenerDirector()
        opener.add_handler(_UnixSocketHandler(socket_path))
        opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
        opener.add_handler(urllib.request.HTTPRedirectHandler())
        opener.add_handler(urllib.request.HTTPErrorProcessor())
        return opener

    # we need to cast the return type depending on the request params
    def json_request(self,
                     method: str,
                     path: str,
                     query: Optional[Dict[str, Any]] = None,
                     body: Optional[Dict[str, Any]] = None
                     ) -> Dict[str, Any]:
        """Make a JSON request to the socket with the given HTTP method and path.

        If query dict is provided, it is encoded and appended as a query string
        to the URL. If body dict is provided, it is serialied as JSON and used
        as the HTTP body (with Content-Type: "application/json"). The resulting
        body is decoded from JSON.
        """
        headers = {'Accept': 'application/json'}
        data = None
        if body is not None:
            data = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'

        response = self.request_raw(method, path, query, headers, data)
        self._ensure_content_type(response.headers, 'application/json')
        raw_resp: Dict[str, Any] = json.loads(response.read())
        return raw_resp

    @staticmethod
    def _ensure_content_type(headers: email.message.Message,
                             expected: 'Literal["multipart/form-data", "application/json"]'):
        """Parse Content-Type header from headers and ensure it's equal to expected.

        Return a dict of any options in the header, e.g., {'boundary': ...}.
        """
        ctype = headers.get_content_type()
        params = headers.get_params() or {}
        options = {key: value for key, value in params if value}
        if ctype != expected:
            raise ProtocolError(f'expected Content-Type {expected!r}, got {ctype!r}')
        return options

    def request_raw(
            self, method: str, path: str,
            query: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, Any]] = None,
            data: Optional[Union[bytes, Generator[bytes, Any, Any]]] = None,
    ) -> http.client.HTTPResponse:
        """Make a request to the socket; return the raw HTTPResponse object."""
        url = self.base_url + path
        if query:
            url = f"{url}?{urllib.parse.urlencode(query, doseq=True)}"

        if headers is None:
            headers = {}
        request = urllib.request.Request(url, method=method, data=data, headers=headers)

        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            code = e.code
            status = e.reason
            try:
                body: Dict[str, Any] = json.loads(e.read())
                message: str = body['error']
            except (OSError, ValueError, KeyError) as e2:
                # Will only happen on read error or if the server sends invalid JSON.
                body: Dict[str, Any] = {}
                message = f'{type(e2).__name__} - {e2}'
            raise APIError(body, code, status, message)
        except urllib.error.URLError as e:
            raise ConnectionError(e.reason)

        return response


class _NotProvidedFlag:
    pass


_not_provided = _NotProvidedFlag()


class _UnixSocketHandler(urllib.request.AbstractHTTPHandler):
    """Implementation of HTTPHandler that uses a named Unix socket."""

    def __init__(self, socket_path: str):
        super().__init__()
        self.socket_path = socket_path

    def http_open(self, req: urllib.request.Request):
        """Override http_open to use a Unix socket connection (instead of TCP)."""
        return self.do_open(_UnixSocketConnection, req,  # type:ignore
                            socket_path=self.socket_path)


class _UnixSocketConnection(http.client.HTTPConnection):
    """Implementation of HTTPConnection that connects to a named Unix socket."""

    def __init__(self, host: str, socket_path: str,
                 timeout: Union[_NotProvidedFlag, float] = _not_provided):
        if timeout is _not_provided:
            super().__init__(host)
        else:
            assert isinstance(timeout, (int, float)), timeout  # type guard for pyright
            super().__init__(host, timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        """Override connect to use Unix socket (instead of TCP socket)."""
        if not hasattr(socket, 'AF_UNIX'):
            raise NotImplementedError(f'Unix sockets not supported on {sys.platform}')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.socket_path)
        if self.timeout is not _not_provided:
            self.sock.settimeout(self.timeout)


class Error(Exception):
    """Base class of most errors raised by the client."""

    def __repr__(self):
        return f'<{type(self).__module__}.{type(self).__name__} {self.args}>'


class ProtocolError(Error):
    """Raised when there's a higher-level protocol error talking to the socket."""


class ConnectionError(Error):
    """Raised when the client can't connect to the socket."""


class APIError(Error):
    """Raised when an HTTP API error occurs talking to the Pebble server."""

    body: Dict[str, Any]
    """Body of the HTTP response, parsed as JSON."""

    code: int
    """HTTP status code."""

    status: str
    """HTTP status string (reason)."""

    message: str
    """Human-readable error message from the API."""

    def __init__(self, body: Dict[str, Any], code: int, status: str, message: str):
        """This shouldn't be instantiated directly."""
        super().__init__(message)  # Makes str(e) return message
        self.body = body
        self.code = code
        self.status = status
        self.message = message

    def __repr__(self):
        return f'APIError({self.body!r}, {self.code!r}, {self.status!r}, {self.message!r})'
