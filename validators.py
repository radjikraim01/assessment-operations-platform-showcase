"""
Input Validation Module
Validates all user inputs to prevent SQL injection, XSS, and DoS attacks

"""

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from typing import Optional, Dict, Any, List
from functools import wraps
from flask import request, jsonify
import re
from datetime import datetime

# ============================================================================
# VALIDATION RULES
# ============================================================================

# Regex patterns for validation
ROLE_ID_PATTERN = re.compile(r'^AOP-[A-Z]{2,3}-[A-Z]{2,10}-[A-Z]{2,5}-R[0-9]L[0-9]B[0-9]-[0-9]{1,4}$')
COMPANY_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s\-\&\.\,]{2,100}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# Maximum lengths to prevent DoS
MAX_TEXT_LENGTH = 5000
MAX_TITLE_LENGTH = 200
MAX_COMPANY_NAME_LENGTH = 100
MAX_NOTES_LENGTH = 1000
MAX_LIST_ITEMS = 50

# Dangerous patterns (XSS prevention)
DANGEROUS_PATTERNS = [
    re.compile(r'<script[^>]*>', re.IGNORECASE),           # <script> open tag (with or without closing)
    re.compile(r'javascript\s*:', re.IGNORECASE),           # javascript: protocol (with optional whitespace)
    re.compile(r'on\w+\s*=', re.IGNORECASE),                # onclick, onerror, etc.
    re.compile(r'<iframe[^>]*>', re.IGNORECASE),
    re.compile(r'<embed[^>]*>', re.IGNORECASE),
    re.compile(r'<object[^>]*>', re.IGNORECASE),
    re.compile(r'<svg[^>]*>', re.IGNORECASE),               # SVG-based XSS
    re.compile(r'<img[^>]*>', re.IGNORECASE),               # img tag injection
    re.compile(r'<link[^>]*>', re.IGNORECASE),              # link tag injection
    re.compile(r'<meta[^>]*>', re.IGNORECASE),              # meta tag injection
    re.compile(r'<form[^>]*>', re.IGNORECASE),              # form injection
    re.compile(r'data\s*:\s*text/html', re.IGNORECASE),    # data: URI with HTML
    re.compile(r'vbscript\s*:', re.IGNORECASE),             # vbscript: protocol
    re.compile(r'expression\s*\(', re.IGNORECASE),          # CSS expression()
]


# ============================================================================
# VALIDATION HELPERS
# ============================================================================

def sanitize_string(text: str, max_length: int = MAX_TEXT_LENGTH) -> str:
    """
    Sanitize string to prevent XSS attacks

    Args:
        text: Input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValueError: If dangerous patterns detected or length exceeded
    """
    if not isinstance(text, str):
        raise ValueError("Input must be a string")

    # Check length
    if len(text) > max_length:
        raise ValueError(f"String exceeds maximum length of {max_length} characters")

    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(text):
            raise ValueError("Dangerous content detected (potential XSS)")

    # Strip leading/trailing whitespace
    return text.strip()


def validate_role_id(role_id: str) -> str:
    """
    Validate AOP role ID format

    Format: AOP-{COUNTRY}-{DEPT}-{POSITION}-{LEVEL}-{NUMBER}
    Example: AOP-QA-HSE-SO-R3L3B3-265

    Args:
        role_id: Role ID string

    Returns:
        Validated role ID

    Raises:
        ValueError: If format is invalid
    """
    if not isinstance(role_id, str):
        raise ValueError("Role ID must be a string")

    if len(role_id) > 50:
        raise ValueError("Role ID too long (max 50 characters)")

    if not ROLE_ID_PATTERN.match(role_id):
        raise ValueError(
            f"Invalid role ID format. Expected: AOP-XX-XXX-XX-R#L#B#-### (got: {role_id})"
        )

    return role_id.upper()


def validate_email(email: str) -> str:
    """
    Validate email format

    Args:
        email: Email address

    Returns:
        Lowercase email

    Raises:
        ValueError: If format is invalid
    """
    if not isinstance(email, str):
        raise ValueError("Email must be a string")

    email = email.strip().lower()

    if len(email) > 255:
        raise ValueError("Email too long (max 255 characters)")

    if not EMAIL_PATTERN.match(email):
        raise ValueError(f"Invalid email format: {email}")

    return email


# ============================================================================
# PYDANTIC MODELS FOR B2B API
# ============================================================================

class CustomJDModel(BaseModel):
    """
    Validation model for an external ATS custom job description
    """
    job_title: str = Field(..., min_length=2, max_length=MAX_TITLE_LENGTH)
    location: Optional[str] = Field(None, max_length=MAX_TITLE_LENGTH)
    department: Optional[str] = Field(None, max_length=MAX_TITLE_LENGTH)
    responsibilities: Optional[List[str]] = Field(None, max_items=MAX_LIST_ITEMS)
    requirements: Optional[Dict[str, Any]] = None
    certifications: Optional[List[str]] = Field(None, max_items=MAX_LIST_ITEMS)
    experience_years: Optional[int] = Field(None, ge=0, le=50)
    education_level: Optional[str] = Field(None, max_length=100)

    @field_validator('job_title', 'location', 'department', 'education_level')
    @classmethod
    def sanitize_text_fields(cls, v):
        """Sanitize text fields to prevent XSS"""
        if v is None:
            return v
        return sanitize_string(v, MAX_TITLE_LENGTH)

    @field_validator('responsibilities', 'certifications')
    @classmethod
    def sanitize_lists(cls, v):
        """Sanitize list items"""
        if v is None:
            return v
        return [sanitize_string(item, MAX_TEXT_LENGTH) for item in v]

    class Config:
        # Allow extra fields from external systems
        extra = "allow"
        # Max object size to prevent DoS
        str_max_length = MAX_TEXT_LENGTH


class B2BInterviewPrepareRequest(BaseModel):
    """
    Validation model for B2B interview preparation request
    POST /api/external/interview/prepare

    Partners send job_title (not internal role_id). Our agents resolve the role automatically.
    """
    company_name: str = Field(..., min_length=2, max_length=MAX_COMPANY_NAME_LENGTH)
    job_title: str = Field(..., min_length=2, max_length=MAX_TITLE_LENGTH)
    custom_jd: Optional[CustomJDModel] = None  # Optional: if None, questions selected randomly

    @field_validator('company_name')
    @classmethod
    def validate_company_name(cls, v):
        """Validate company name format"""
        v = sanitize_string(v, MAX_COMPANY_NAME_LENGTH)

        if not COMPANY_NAME_PATTERN.match(v):
            raise ValueError(
                "Company name contains invalid characters. "
                "Allowed: letters, numbers, spaces, hyphens, ampersands, periods, commas"
            )

        return v

    @field_validator('job_title')
    @classmethod
    def sanitize_job_title(cls, v):
        """Sanitize job title"""
        return sanitize_string(v, MAX_TITLE_LENGTH)

    class Config:
        # Strict validation
        extra = "forbid"
        str_max_length = MAX_TEXT_LENGTH


# ============================================================================
# PYDANTIC MODELS FOR B2B ANSWER EVALUATION
# ============================================================================

class CandidateAnswer(BaseModel):
    """Single candidate answer for evaluation"""
    question_id: str = Field(..., min_length=1, max_length=100)
    answer_text: str = Field(..., min_length=1, max_length=MAX_TEXT_LENGTH)

    @field_validator('answer_text')
    @classmethod
    def sanitize_answer(cls, v):
        return sanitize_string(v, MAX_TEXT_LENGTH)

    class Config:
        extra = "forbid"


class B2BEvaluateAnswersRequest(BaseModel):
    """
    Validation model for B2B answer evaluation
    POST /api/external/evaluate-answers
    """
    request_id: int = Field(..., ge=1)
    candidate_answers: List[CandidateAnswer] = Field(..., min_length=1, max_length=15)

    class Config:
        extra = "forbid"


# ============================================================================
# PYDANTIC MODELS FOR ADMIN DASHBOARD
# ============================================================================

class AdminLoginRequest(BaseModel):
    """
    Validation model for admin login
    POST /api/admin/login
    """
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator('email')
    @classmethod
    def validate_email_field(cls, v):
        """Validate email format"""
        return validate_email(v)

    @field_validator('password')
    @classmethod
    def validate_password_field(cls, v):
        """Ensure password meets minimum requirements"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password too long (max 128 characters)")
        return v

    class Config:
        extra = "forbid"


class ApprovalRequest(BaseModel):
    """
    Validation model for approval request
    POST /api/dashboard/b2b-requests/{request_id}/approve
    """
    notes: Optional[str] = Field(None, max_length=MAX_NOTES_LENGTH)

    @field_validator('notes')
    @classmethod
    def sanitize_notes(cls, v):
        """Sanitize approval notes"""
        if v is None:
            return "Approved"
        return sanitize_string(v, MAX_NOTES_LENGTH)

    class Config:
        extra = "forbid"


class DenialRequest(BaseModel):
    """
    Validation model for denial request
    POST /api/dashboard/b2b-requests/{request_id}/deny
    """
    reason: str = Field(..., min_length=1, max_length=MAX_NOTES_LENGTH)

    @field_validator('reason')
    @classmethod
    def sanitize_reason(cls, v):
        """Sanitize denial reason"""
        v = sanitize_string(v, MAX_NOTES_LENGTH)

        return v

    class Config:
        extra = "forbid"


# ============================================================================
# VALIDATION DECORATORS FOR FLASK ROUTES
# ============================================================================

from functools import wraps
from flask import request, jsonify
from pydantic import ValidationError
from error_helpers import error_response


def validate_request(model: BaseModel):
    """
    Decorator to validate Flask request body against Pydantic model

    Usage:
        @app.route('/api/endpoint', methods=['POST'])
        @validate_request(B2BInterviewPrepareRequest)
        def my_endpoint():
            data = request.validated_data  # Validated Pydantic model
            ...

    Args:
        model: Pydantic model class to validate against

    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get JSON data
                json_data = request.get_json(force=True)

                if json_data is None:
                    return error_response('Request body must be valid JSON', 400)

                # Validate against Pydantic model
                validated = model(**json_data)

                # Attach validated data to request object
                request.validated_data = validated

                return f(*args, **kwargs)

            except ValidationError as e:
                # Pydantic validation error
                errors = []
                for error in e.errors():
                    field = '.'.join(str(x) for x in error['loc'])
                    errors.append(f"{field}: {error['msg']}")

                return error_response('Validation failed', 400, details=errors)

            except Exception as e:
                # Other errors (malformed JSON, etc.)
                return error_response(f'Invalid request: {str(e)}', 400)

        return decorated_function
    return decorator


def validate_path_param(param_name: str, validator_func):
    """
    Decorator to validate Flask path parameters

    Usage:
        @app.route('/api/request/<int:request_id>')
        @validate_path_param('request_id', lambda x: 0 < x < 1000000)
        def my_endpoint(request_id):
            ...

    Args:
        param_name: Name of path parameter to validate
        validator_func: Function that takes value and returns True if valid

    Returns:
        Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            param_value = kwargs.get(param_name)

            try:
                if not validator_func(param_value):
                    return error_response(f'Invalid {param_name}: {param_value}', 400)
            except Exception as e:
                return error_response(f'Invalid {param_name}: {str(e)}', 400)

            return f(*args, **kwargs)

        return decorated_function
    return decorator


# ============================================================================
# SQL INJECTION PREVENTION HELPERS
# ============================================================================

def validate_sql_identifier(identifier: str, max_length: int = 63) -> str:
    """
    Validate SQL identifier (table name, column name, etc.)
    PostgreSQL max identifier length is 63 characters

    Args:
        identifier: SQL identifier to validate
        max_length: Maximum allowed length

    Returns:
        Validated identifier

    Raises:
        ValueError: If identifier is invalid
    """
    if not isinstance(identifier, str):
        raise ValueError("SQL identifier must be a string")

    # Check length
    if len(identifier) > max_length:
        raise ValueError(f"SQL identifier too long (max {max_length} characters)")

    # Must start with letter or underscore
    if not re.match(r'^[a-zA-Z_]', identifier):
        raise ValueError("SQL identifier must start with letter or underscore")

    # Can only contain letters, numbers, underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', identifier):
        raise ValueError("SQL identifier can only contain letters, numbers, and underscores")

    # Prevent SQL keywords (basic check)
    sql_keywords = {'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'table'}
    if identifier.lower() in sql_keywords:
        raise ValueError(f"SQL identifier cannot be a reserved keyword: {identifier}")

    return identifier


def is_safe_integer(value: Any, min_val: int = 0, max_val: int = 2147483647) -> bool:
    """
    Check if value is a safe integer (prevents integer overflow attacks)

    Args:
        value: Value to check
        min_val: Minimum allowed value
        max_val: Maximum allowed value (PostgreSQL INT max)

    Returns:
        True if safe integer, False otherwise
    """
    try:
        int_val = int(value)
        return min_val <= int_val <= max_val
    except (ValueError, TypeError):
        return False


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Validation functions
    'sanitize_string',
    'validate_role_id',
    'validate_email',
    'validate_sql_identifier',
    'is_safe_integer',

    # Pydantic models
    'CustomJDModel',
    'B2BInterviewPrepareRequest',
    'AdminLoginRequest',
    'ApprovalRequest',
    'DenialRequest',

    # Decorators
    'validate_request',
    'validate_path_param',

    # Constants
    'MAX_TEXT_LENGTH',
    'MAX_TITLE_LENGTH',
    'MAX_COMPANY_NAME_LENGTH',
    'MAX_NOTES_LENGTH',
]

