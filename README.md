# JWTOperation

Python で JWT 認証の流れを確認するためのリポジトリ。

このリポジトリでは、次の流れを追えるようにしている。

- アカウントを作成する
- refresh token を発行する
- refresh token をストレージに保存する
- 保存済み refresh token を検証する
- refresh token から access token を発行する

## 概要

JWT を使った認証では、主に次の 2 種類のトークンを使う。

- access token
- refresh token

access token は API 呼び出しに使う短命なトークン。  
refresh token は access token の期限切れ後に、新しい access token を再発行するための長命なトークン。

JWT の発行、署名検証、refresh token の保存、refresh token からの access token 再発行までを実装している。

## JWT の仕組み

JWT は署名付きデータの一種で、一般的には次の 3 つの部分を `.` で連結した文字列になる。

- Header
- Payload
- Signature

### Header

Header には、署名アルゴリズムなどのメタ情報が入る。  
このリポジトリでは `HS256` を使う。

### Payload

Payload には、トークンの中身を入れる。  
この実装では主に次の情報を使う。

- `sub`: ユーザー ID
- `scopes`: 権限一覧
- `exp`: 有効期限
- `jti`: トークンを一意に識別する ID
- `type`: `access` または `refresh`

### Signature

Signature は Header と Payload を秘密鍵で署名したもの。  
この署名により、受け取ったトークンが改ざんされていないかを検証できる。

このリポジトリでは、`settings.py` に定義した `JWT_SECRET` を署名鍵として使う。

## 実装の流れ

### 1. アカウントを作成する

`main.py` で `Account` を作成する。  
ここでは `demo-user-001` に `role1` と `admin` の権限を持たせる。

### 2. refresh token を発行する

`token_manager.py` の `create_refresh_token_from_account()` が refresh token を発行する。

内部では次の値を組み立てる。

- `sub` にユーザー ID を入れる
- `scopes` に権限を入れる
- `exp` に有効期限を入れる
- `jti` に ULID を入れる
- `type` に `refresh` を入れる

その後、`python-jose` の `jwt.encode()` で署名する。

### 3. refresh token をファイルに保存する

発行した refresh token は `refresh_tokens.txt` に保存する。  
このファイルは簡易ストレージとして使う。

保存形式は JSON Lines。1 行が 1 件の refresh token レコードに対応する。

保存項目は次のとおり。

- `token`
- `jti`
- `sub`
- `exp`

ファイルの読み書きは `aiofiles` を使って非同期で行う。  
また、read-modify-write が競合しないように `asyncio.Lock` を使う。

### 4. refresh token を検証する

`parse_and_validate_refresh_token()` では、次の 2 段階で確認する。

1. JWT の署名を検証する
2. `refresh_tokens.txt` にその token が保存されているか確認する

1 つ目の署名検証では `jwt.decode()` を使う。  
ここで秘密鍵とアルゴリズムを使い、トークンが改ざんされていないかを確認する。

2 つ目の保存確認を入れているのは、refresh token をサーバ側でも管理するため。  
JWT 自体は自己完結なトークンだが、refresh token は失効管理が必要になることが多いため、この実装ではファイルに保存して扱う。

### 5. refresh token から access token を発行する

`create_access_token_from_refresh_token()` は、検証済み refresh token の `sub` と `scopes` を使って、新しい access token を発行する。

access token には `type=access` を入れる。  
また、refresh token より短い有効期限を持たせる。

## ファイル構成

- `main.py`
  実行用のエントリポイント。アカウント作成から token 発行までを順に表示する。
- `schemas.py`
  Pydantic モデル、Enum、例外クラスなどの定義をまとめる。
- `token_manager.py`
  JWT の発行、検証、refresh token ストアの読み書きを担当する。
- `settings.py`
  秘密鍵、アルゴリズム、有効期限、保存先ファイルなどの設定をまとめる。
- `refresh_tokens.txt`
  refresh token 保存ファイル。

## 実行方法

依存ライブラリが入った環境で次を実行する。

```bash
./venv/bin/python -B main.py
```

実行すると、次の流れを確認できる。

- 最初に `refresh_tokens.txt` を空にする
- アカウント情報を表示する
- refresh token を発行する
- `refresh_tokens.txt` に refresh token を保存する
- refresh token から access token を発行する

## 設定

`settings.py` では次の値を管理する。

- `JWT_SECRET`
- `JWT_ALGORITHM`
- `ACCESS_TOKEN_EXP_MINUTES`
- `REFRESH_TOKEN_EXP_MINUTES`
- `REFRESH_TOKEN_STORE`

挙動を変えたい場合は、ここを編集する。

## 注意

これは本番向け実装ではない。  
特に次の点は簡略化している。

- 秘密鍵をコードにハードコードしている
- refresh token を平文でファイル保存している
- DB ではなくテキストファイルを使っている
- OAuth 2.0 の完全な実装ではない

実装は最小構成に寄せている。  
署名付きトークンの構造、refresh token の別管理、access token の再発行という流れを確認できる構成にしている。