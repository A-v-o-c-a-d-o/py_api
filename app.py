from typing import Annotated
from google.oauth2 import id_token
from google.auth.transport import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, HTTPBearer
from pydantic import BaseModel


CLIENT_ID = "926777041377-pqbbmct0pr1bi7vu9kmptm67boikpfmt.apps.googleusercontent.com"


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()


def fake_hash_password(password: str):
    return "fakehashed" + password


oauth2_scheme = HTTPBearer()


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def fake_decode_token(token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjJkOWE1ZWY1YjEyNjIzYzkxNjcxYTcwOTNjYjMyMzMzM2NkMDdkMDkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDkzMzE0MDE0NzAwNjk4NjYzNDYiLCJhdF9oYXNoIjoicHBVUjNWLWxQQVF5TW5EMXpFM1lZQSIsIm5hbWUiOiJUdWFuIEFuaCBMZSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQWNIVHRmSDdPZHNRRXhkYllGMWlrZG5mbElRTEJFU2cxWXFXZy1FdEtRdGhBPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IlR1YW4gQW5oIiwiZmFtaWx5X25hbWUiOiJMZSIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjg1NTIxNTI5LCJleHAiOjE2ODU1MjUxMjl9.kwsjENBDDnN8GIS3OTQLIEgH1Z5gPVGjY4BhX8hvoQJQYj0kPgriFtf4fJ99TE1FV5zsyEnGMTxWkp1g1hwz-qHtMfqGwlkwAnZrdlbkXKTlSC_NO1QnbZREoWgLjJlxynSL-5OGAIt7M-a29WLBHNiBRHeyTfe_Si_we7aUF5NfckBzHRysGve8QI93Tw9Lmu1S3dCA2qz5IjQ6E9SS2WI6i74ulLqZlg0xd5rQ35JLZV_5MYNKTmKPWkFL9sBYVTzJ_GX3v_lsH7p0wo2KtLTdmtbVl6yaIaznAXA1kMJko5kbPINRBW6t6s-f4iIktw1of5gwGuV_s5TD-keqJA'):
    idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

    # Or, if multiple clients access the backend server:
    # idinfo = id_token.verify_oauth2_token(token, requests.Request())
    # if idinfo['aud'] not in [CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]:
    #     raise ValueError('Could not verify audience.')

    # If auth request is from a G Suite domain:
    # if idinfo['hd'] != GSUITE_DOMAIN_NAME:
    #     raise ValueError('Wrong hosted domain.')

    # ID token is valid. Get the user's Google Account ID from the decoded token.
    userid = idinfo['sub']
    # This doesn't provide any security at all
    # Check the next version
    # user = get_user(fake_users_db, token)
    return userid


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    userid = fake_decode_token(token)
    if not userid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return userid


async def get_current_active_user(
    current_user: Annotated[str, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = fake_users_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": user.username, "token_type": "bearer"}


@app.get("/users/me")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host='localhost', port=8000)