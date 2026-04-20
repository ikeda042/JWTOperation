import asyncio

from settings import REFRESH_TOKEN_STORE
from schemas import Account, Scope
from token_manager import TokenManager


def create_demo_account() -> Account:
    return Account(id="demo-user-001", scopes={Scope.role1, Scope.admin})


def print_refresh_token_store() -> None:
    contents = REFRESH_TOKEN_STORE.read_text(encoding="utf-8").strip()
    print(f"\nrefresh token store: {REFRESH_TOKEN_STORE.name}")
    print(contents if contents else "(empty)")


async def run_demo() -> None:
    await TokenManager.reset_refresh_token_store()
    print("0. refresh token store")
    print_refresh_token_store()

    account = create_demo_account()
    print("\n1. account")
    print(account.model_dump())

    refresh_token = await TokenManager.create_refresh_token_from_account(account)
    refresh_payload = await TokenManager.parse_and_validate_refresh_token(refresh_token)
    print("\n2. refresh token")
    print(refresh_token)
    print(refresh_payload.model_dump())
    print_refresh_token_store()

    access_token = await TokenManager.create_access_token_from_refresh_token(refresh_token)
    access_payload = TokenManager.parse_and_validate_access_token(access_token)
    print("\n3. access token from refresh token")
    print(access_token)
    print(access_payload.model_dump())


if __name__ == "__main__":
    asyncio.run(run_demo())
