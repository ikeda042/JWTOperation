import asyncio
import json
from datetime import datetime, timedelta, timezone
from time import time
from typing import TypeVar, TypedDict

import aiofiles
from jose import JWTError, jwt
from ulid import monotonic as ulid

from settings import (
    ACCESS_TOKEN_EXP_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET,
    REFRESH_TOKEN_EXP_MINUTES,
    REFRESH_TOKEN_STORE,
)
from schemas import (
    AccessToken,
    AccessTokenCreate,
    Account,
    AuthorizationException,
    InvalidAccessToken,
    InvalidRefreshToken,
    RefreshToken,
    RefreshTokenCreate,
    TokenType,
)

TokenPayload = TypeVar("TokenPayload", AccessToken, RefreshToken)
_refresh_token_store_lock: asyncio.Lock | None = None

class RefreshTokenRecord(TypedDict):
    token: str
    jti: str
    sub: str
    exp: int


def _get_refresh_token_store_lock() -> asyncio.Lock:
    global _refresh_token_store_lock
    if _refresh_token_store_lock is None:
        _refresh_token_store_lock = asyncio.Lock()
    return _refresh_token_store_lock


async def _ensure_refresh_token_store() -> None:
    if REFRESH_TOKEN_STORE.exists():
        return
    async with aiofiles.open(REFRESH_TOKEN_STORE, "a", encoding="utf-8"):
        pass


async def _read_refresh_token_records() -> list[RefreshTokenRecord]:
    await _ensure_refresh_token_store()
    async with aiofiles.open(REFRESH_TOKEN_STORE, encoding="utf-8") as store:
        contents = await store.read()
    records: list[RefreshTokenRecord] = []
    for line in contents.splitlines():
        if not line.strip():
            continue
        records.append(json.loads(line))
    return records


async def _write_refresh_token_records(records: list[RefreshTokenRecord]) -> None:
    await _ensure_refresh_token_store()
    serialized = "\n".join(
        json.dumps(record, ensure_ascii=True, sort_keys=True) for record in records
    )
    if serialized:
        serialized += "\n"
    async with aiofiles.open(REFRESH_TOKEN_STORE, "w", encoding="utf-8") as store:
        await store.write(serialized)


def get_ulid() -> str:
    return ulid.new().str


def create_access_token(data: AccessTokenCreate) -> tuple[str, AccessToken]:
    to_encode = {**data}
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES)
    exp = int(expire.timestamp())
    jti: str = get_ulid()
    to_encode.update({"exp": exp, "jti": jti, "type": TokenType.access})
    encoded_jwt: str = jwt.encode(
        to_encode,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return encoded_jwt, AccessToken(**to_encode)


def create_refresh_token(
    data: RefreshTokenCreate,
    expire_limit: datetime | None = None,
) -> tuple[str, RefreshToken]:
    to_encode = {**data}
    expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXP_MINUTES)
    if expire_limit is not None:
        expire = expire if expire < expire_limit else expire_limit
    exp = int(expire.timestamp())
    jti: str = get_ulid()
    to_encode.update({"exp": exp, "jti": jti, "type": TokenType.refresh})
    encoded_jwt: str = jwt.encode(
        to_encode,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return encoded_jwt, RefreshToken(**to_encode)


def create_access_token_from_account(account: Account) -> str:
    access_token, _ = create_access_token(
        data={
            "sub": account.id,
            "scopes": list(account.scopes),
        }
    )
    return access_token


async def create_refresh_token_from_account(
    account: Account,
    expire_limit: datetime | None = None,
) -> str:
    refresh_token, refresh_token_payload = create_refresh_token(
        data={
            "sub": account.id,
            "scopes": list(account.scopes),
        },
        expire_limit=expire_limit,
    )
    async with _get_refresh_token_store_lock():
        records = await _read_refresh_token_records()
        records.append(
            {
                "token": refresh_token,
                "jti": refresh_token_payload.jti,
                "sub": refresh_token_payload.sub,
                "exp": refresh_token_payload.exp,
            }
        )
        await _write_refresh_token_records(records)
    return refresh_token


async def read_refresh_token_store() -> list[RefreshTokenRecord]:
    async with _get_refresh_token_store_lock():
        return await _read_refresh_token_records()


async def reset_refresh_token_store() -> None:
    async with _get_refresh_token_store_lock():
        await _write_refresh_token_records([])


def _decode_token(
    token: str,
    payload_model: type[TokenPayload],
    error_cls: type[AuthorizationException],
) -> TokenPayload:
    try:
        return payload_model(
            **jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
            )
        )
    except JWTError as exc:
        raise error_cls() from exc


def parse_and_validate_access_token(token: str) -> AccessToken:
    return _decode_token(token, AccessToken, InvalidAccessToken)


async def parse_and_validate_refresh_token(token: str) -> RefreshToken:
    payload = _decode_token(token, RefreshToken, InvalidRefreshToken)
    records = await read_refresh_token_store()
    exists = any(
        record["jti"] == payload.jti and record["token"] == token for record in records
    )
    if not exists:
        raise InvalidRefreshToken()
    return payload


async def create_access_token_from_refresh_token(refresh_token: str) -> str:
    refresh_payload = await parse_and_validate_refresh_token(refresh_token)
    account = Account(id=refresh_payload.sub, scopes=set(refresh_payload.scopes))
    return create_access_token_from_account(account)


async def invalidate_refresh_token(refresh_token: RefreshToken) -> None:
    current_time = int(time())
    async with _get_refresh_token_store_lock():
        records = await _read_refresh_token_records()
        remaining_records = [
            record
            for record in records
            if record["jti"] != refresh_token.jti
            and not (
                record["sub"] == refresh_token.sub and record["exp"] < current_time
            )
        ]
        await _write_refresh_token_records(remaining_records)
