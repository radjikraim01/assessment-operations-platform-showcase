"""
Standardized Error Response Helper
====================================
Single canonical error format for all API endpoints.

Usage:
    from error_helpers import error_response

    return error_response('User not found', 404)
    return error_response('Validation failed', 400, code='VALIDATION_ERROR', details=errors)

"""

from flask import jsonify

_DEFAULT_CODES = {
    400: 'VALIDATION_ERROR',
    401: 'AUTH_ERROR',
    403: 'FORBIDDEN',
    404: 'NOT_FOUND',
    409: 'CONFLICT',
    413: 'PAYLOAD_TOO_LARGE',
    500: 'SERVER_ERROR',
    503: 'SERVICE_UNAVAILABLE',
}


def error_response(message, status_code, code=None, details=None):
    """
    Build a standardized JSON error response.

    Args:
        message: Human-readable error message
        status_code: HTTP status code (e.g. 400, 404, 500)
        code: Machine-readable error code (e.g. 'ROLE_NOT_FOUND').
              Defaults based on status_code.
        details: Optional extra context (validation errors list, etc.)

    Returns:
        (Response, status_code) tuple ready to return from a Flask route
    """
    body = {
        'status': 'error',
        'code': code or _DEFAULT_CODES.get(status_code, 'UNKNOWN_ERROR'),
        'message': message,
        'error': message,   # backward compat: frontend reads data.error
    }
    if details is not None:
        body['details'] = details
    return jsonify(body), status_code

