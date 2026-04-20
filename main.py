import os

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
import uvicorn

from schemas import (
    Account,
    AuthorizationException,
    InvalidPassword,
    InvalidTokenRequest,
    NotEnoughPermissions,
    OAuth2GrantType,
    OAuth2RequestForm,
    Scope,
    UserNotFound,
)
from settings import ACCESS_TOKEN_EXP_MINUTES
from token_manager import TokenManager

API_BASE_PATH = "/api/v1"

DEMO_USERNAME = os.getenv("DEMO_USERNAME", "demo-user-001")
DEMO_PASSWORD = os.getenv("DEMO_PASSWORD", "demo-password")
DEMO_SCOPES = {Scope.role1, Scope.admin}

app = FastAPI(
    title="JWTOperation API",
    docs_url=f"{API_BASE_PATH}/docs",
    openapi_url=f"{API_BASE_PATH}/openapi.json",
)


def _authenticate_user(username: str, password: str) -> Account:
    if username != DEMO_USERNAME:
        raise UserNotFound()
    if password != DEMO_PASSWORD:
        raise InvalidPassword()
    return Account(id=DEMO_USERNAME, scopes=DEMO_SCOPES)


def _resolve_requested_scopes(
    available_scopes: set[Scope],
    requested_scopes: list[str],
) -> set[Scope]:
    if not requested_scopes:
        return available_scopes

    try:
        parsed_scopes = {Scope(scope) for scope in requested_scopes}
    except ValueError as exc:
        raise InvalidTokenRequest("scope includes unknown value.") from exc

    if not parsed_scopes.issubset(available_scopes):
        raise NotEnoughPermissions("requested scope is not allowed.")
    return parsed_scopes


@app.exception_handler(AuthorizationException)
async def authorization_exception_handler(request, exc: AuthorizationException) -> JSONResponse:
    return JSONResponse(status_code=exc.code, content={"detail": exc.message})


@app.get(f"{API_BASE_PATH}/")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post(f"{API_BASE_PATH}/oauth/token")
async def issue_token(form_data: OAuth2RequestForm = Depends()) -> dict[str, str | int]:
    if form_data.grant_type == OAuth2GrantType.password:
        if form_data.username is None or form_data.password is None:
            raise InvalidTokenRequest("username/password are required for password grant.")

        account = _authenticate_user(form_data.username, form_data.password)
        account = Account(
            id=account.id,
            scopes=_resolve_requested_scopes(account.scopes, form_data.scopes),
        )
        refresh_token = await TokenManager.create_refresh_token_from_account(account)
        access_token = TokenManager.create_access_token_from_account(account)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXP_MINUTES * 60,
            "scope": " ".join(sorted(scope.value for scope in account.scopes)),
            "refresh_token": refresh_token,
        }

    if form_data.refresh_token is None:
        raise InvalidTokenRequest("refresh_token is required for refresh_token grant.")

    refresh_payload = await TokenManager.parse_and_validate_refresh_token(form_data.refresh_token)
    account = Account(
        id=refresh_payload.sub,
        scopes=_resolve_requested_scopes(
            set(refresh_payload.scopes),
            form_data.scopes,
        ),
    )
    access_token = TokenManager.create_access_token_from_account(account)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXP_MINUTES * 60,
        "scope": " ".join(sorted(scope.value for scope in account.scopes)),
    }


if __name__ == "__main__":
    reload_env = os.getenv("UVICORN_RELOAD", "").lower()
    uvicorn.run(
        app,
        host=os.getenv("UVICORN_HOST", "127.0.0.1"),
        port=int(os.getenv("UVICORN_PORT", "8000")),
        reload=reload_env in {"1", "true", "yes", "on"},
    )
