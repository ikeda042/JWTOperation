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
    JWT_PRIVATE_KEY,
    JWT_PUBLIC_KEY,
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

class RefreshTokenRecord(TypedDict):
    token: str
    jti: str
    sub: str
    exp: int


class TokenManager:
    _refresh_token_store_lock: asyncio.Lock | None = None
    _SUPPORTED_ALGORITHMS = {"HS256", "RS256", "ES256"}

    @classmethod
    def _validate_algorithm(cls) -> None:
        if JWT_ALGORITHM not in cls._SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported JWT_ALGORITHM: {JWT_ALGORITHM}. "
                f"Supported: {sorted(cls._SUPPORTED_ALGORITHMS)}"
            )
        if JWT_ALGORITHM == "HS256" and not JWT_SECRET:
            raise ValueError("JWT_SECRET is required when JWT_ALGORITHM=HS256.")
        if JWT_ALGORITHM in {"RS256", "ES256"} and (not JWT_PRIVATE_KEY or not JWT_PUBLIC_KEY):
            raise ValueError(
                "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required when "
                "JWT_ALGORITHM is RS256 or ES256."
            )

    @classmethod
    def _encode_key(cls) -> str:
        cls._validate_algorithm()
        if JWT_ALGORITHM == "HS256":
            return JWT_SECRET
        return JWT_PRIVATE_KEY

    @classmethod
    def _decode_key(cls) -> str:
        cls._validate_algorithm()
        if JWT_ALGORITHM == "HS256":
            return JWT_SECRET
        return JWT_PUBLIC_KEY

    @classmethod
    def _get_refresh_token_store_lock(cls) -> asyncio.Lock:
        if cls._refresh_token_store_lock is None:
            cls._refresh_token_store_lock = asyncio.Lock()
        return cls._refresh_token_store_lock

    @classmethod
    async def _ensure_refresh_token_store(cls) -> None:
        if REFRESH_TOKEN_STORE.exists():
            return
        async with aiofiles.open(REFRESH_TOKEN_STORE, "a", encoding="utf-8"):
            pass

    @classmethod
    async def _read_refresh_token_records(cls) -> list[RefreshTokenRecord]:
        await cls._ensure_refresh_token_store()
        async with aiofiles.open(REFRESH_TOKEN_STORE, encoding="utf-8") as store:
            contents = await store.read()
        records: list[RefreshTokenRecord] = []
        for line in contents.splitlines():
            if not line.strip():
                continue
            records.append(json.loads(line))
        return records

    @classmethod
    async def _write_refresh_token_records(cls, records: list[RefreshTokenRecord]) -> None:
        await cls._ensure_refresh_token_store()
        serialized = "\n".join(
            json.dumps(record, ensure_ascii=True, sort_keys=True) for record in records
        )
        if serialized:
            serialized += "\n"
        async with aiofiles.open(REFRESH_TOKEN_STORE, "w", encoding="utf-8") as store:
            await store.write(serialized)

    @classmethod
    def get_ulid(cls) -> str:
        return ulid.new().str

    @classmethod
    def create_access_token(cls, data: AccessTokenCreate) -> tuple[str, AccessToken]:
        to_encode = {**data}
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES)
        exp = int(expire.timestamp())
        jti: str = cls.get_ulid()
        to_encode.update({"exp": exp, "jti": jti, "type": TokenType.access})
        encoded_jwt: str = jwt.encode(
            to_encode,
            cls._encode_key(),
            algorithm=JWT_ALGORITHM,
        )
        return encoded_jwt, AccessToken(**to_encode)

    @classmethod
    def create_refresh_token(
        cls,
        data: RefreshTokenCreate,
        expire_limit: datetime | None = None,
    ) -> tuple[str, RefreshToken]:
        to_encode = {**data}
        expire = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXP_MINUTES)
        if expire_limit is not None:
            expire = expire if expire < expire_limit else expire_limit
        exp = int(expire.timestamp())
        jti: str = cls.get_ulid()
        to_encode.update({"exp": exp, "jti": jti, "type": TokenType.refresh})
        encoded_jwt: str = jwt.encode(
            to_encode,
            cls._encode_key(),
            algorithm=JWT_ALGORITHM,
        )
        return encoded_jwt, RefreshToken(**to_encode)

    @classmethod
    def create_access_token_from_account(cls, account: Account) -> str:
        access_token, _ = cls.create_access_token(
            data={
                "sub": account.id,
                "scopes": list(account.scopes),
            }
        )
        return access_token

    @classmethod
    async def create_refresh_token_from_account(
        cls,
        account: Account,
        expire_limit: datetime | None = None,
    ) -> str:
        refresh_token, refresh_token_payload = cls.create_refresh_token(
            data={
                "sub": account.id,
                "scopes": list(account.scopes),
            },
            expire_limit=expire_limit,
        )
        async with cls._get_refresh_token_store_lock():
            records = await cls._read_refresh_token_records()
            records.append(
                {
                    "token": refresh_token,
                    "jti": refresh_token_payload.jti,
                    "sub": refresh_token_payload.sub,
                    "exp": refresh_token_payload.exp,
                }
            )
            await cls._write_refresh_token_records(records)
        return refresh_token

    @classmethod
    async def read_refresh_token_store(cls) -> list[RefreshTokenRecord]:
        async with cls._get_refresh_token_store_lock():
            return await cls._read_refresh_token_records()

    @classmethod
    async def reset_refresh_token_store(cls) -> None:
        async with cls._get_refresh_token_store_lock():
            await cls._write_refresh_token_records([])

    @classmethod
    def _decode_token(
        cls,
        token: str,
        payload_model: type[TokenPayload],
        error_cls: type[AuthorizationException],
    ) -> TokenPayload:
        try:
            return payload_model(
                **jwt.decode(
                    token,
                    cls._decode_key(),
                    algorithms=[JWT_ALGORITHM],
                )
            )
        except JWTError as exc:
            raise error_cls() from exc

    @classmethod
    def parse_and_validate_access_token(cls, token: str) -> AccessToken:
        return cls._decode_token(token, AccessToken, InvalidAccessToken)

    @classmethod
    async def parse_and_validate_refresh_token(cls, token: str) -> RefreshToken:
        payload = cls._decode_token(token, RefreshToken, InvalidRefreshToken)
        records = await cls.read_refresh_token_store()
        exists = any(
            record["jti"] == payload.jti and record["token"] == token for record in records
        )
        if not exists:
            raise InvalidRefreshToken()
        return payload

    @classmethod
    async def create_access_token_from_refresh_token(cls, refresh_token: str) -> str:
        refresh_payload = await cls.parse_and_validate_refresh_token(refresh_token)
        account = Account(id=refresh_payload.sub, scopes=set(refresh_payload.scopes))
        return cls.create_access_token_from_account(account)

    @classmethod
    async def invalidate_refresh_token(cls, refresh_token: RefreshToken) -> None:
        current_time = int(time())
        async with cls._get_refresh_token_store_lock():
            records = await cls._read_refresh_token_records()
            remaining_records = [
                record
                for record in records
                if record["jti"] != refresh_token.jti
                and not (
                    record["sub"] == refresh_token.sub and record["exp"] < current_time
                )
            ]
            await cls._write_refresh_token_records(remaining_records)
