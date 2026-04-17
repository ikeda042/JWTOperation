from enum import StrEnum
from typing import Literal, TypedDict

from fastapi import Form, status
from pydantic import BaseModel, ConfigDict


class BaseException(Exception):
    def __init__(
        self,
        message: str = "Internal Error",
        code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    ):
        super().__init__(message)
        self.code = code
        self.message = message


class OAuthGrantType(StrEnum):
    password = "password"
    refresh_token = "refresh_token"


class TokenType(StrEnum):
    access = "access"
    refresh = "refresh"


class Scope(StrEnum):
    role1 = "role1"
    role2 = "role2"
    admin = "admin"


class AccessTokenCreate(TypedDict):
    sub: str
    scopes: list[Scope]


class RefreshTokenCreate(TypedDict):
    sub: str
    scopes: list[Scope]


class BaseModelImmutable(BaseModel):
    model_config = ConfigDict(frozen=False, from_attributes=True)


class Account(BaseModelImmutable):
    id: str
    scopes: set[Scope] = set()


class AccessToken(BaseModelImmutable):
    type: Literal[TokenType.access]
    jti: str
    sub: str
    exp: int
    scopes: set[Scope]


class RefreshToken(BaseModelImmutable):
    type: Literal[TokenType.refresh]
    jti: str
    sub: str
    exp: int
    scopes: set[Scope]


class OAuth2RequestForm:
    def __init__(
        self,
        grant_type: OAuthGrantType = Form(),
        username: str | None = Form(default=None),
        password: str | None = Form(default=None),
        scope: str = Form(default=""),
        refresh_token: str | None = Form(default=None),
    ) -> None:
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.scopes = scope.split()
        self.refresh_token = refresh_token


class OAuth2PasswordRequest(BaseModelImmutable):
    grant_type: Literal[OAuthGrantType.password]
    username: str
    password: str
    scopes: set[Scope]


class OAuth2RefreshRequest(BaseModelImmutable):
    grant_type: Literal[OAuthGrantType.refresh_token]
    scopes: set[Scope]
    refresh_token: str


class AuthorizationException(BaseException):
    def __init__(
        self,
        message: str = "Authorization error",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class InvalidAccessToken(AuthorizationException):
    def __init__(
        self,
        message: str = "Access token is invalid.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class InvalidRefreshToken(AuthorizationException):
    def __init__(
        self,
        message: str = "Refresh token is invalid.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class InvalidTokenRequest(AuthorizationException):
    def __init__(
        self,
        message: str = "Token request parameters are invalid.",
        code: int = status.HTTP_400_BAD_REQUEST,
    ):
        super().__init__(message, code)


class NoToken(AuthorizationException):
    def __init__(
        self,
        message: str = "No Token",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class NotEnoughPermissions(AuthorizationException):
    def __init__(
        self,
        message: str = "Not enough permissions",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class InvalidOrigin(AuthorizationException):
    def __init__(
        self,
        message: str = "Invalid origin.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class UserNotFound(AuthorizationException):
    def __init__(
        self,
        message: str = "User not found.",
        code: int = status.HTTP_404_NOT_FOUND,
    ):
        super().__init__(message, code)


class UserAlreadyExists(AuthorizationException):
    def __init__(
        self,
        message: str = "User already exists.",
        code: int = status.HTTP_409_CONFLICT,
    ):
        super().__init__(message, code)


class AccountLocked(AuthorizationException):
    def __init__(
        self,
        message: str = "Your account is locked.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class InvalidPassword(AuthorizationException):
    def __init__(
        self,
        message: str = "Invalid password",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class PasswordResetRequired(AuthorizationException):
    def __init__(
        self,
        message: str = "Password reset required.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)


class EmailNotVerified(AuthorizationException):
    def __init__(
        self,
        message: str = "Email is not verified.",
        code: int = status.HTTP_401_UNAUTHORIZED,
    ):
        super().__init__(message, code)
