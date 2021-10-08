from datetime import datetime, timedelta

from typing import Optional
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
from fastapi import security
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, oauth2, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse

from starlette.responses import FileResponse

from passlib.context import CryptContext
from jose import JWTError, jwt

from pydantic import BaseModel

import os
import uuid
import secrets

from starlette.status import HTTP_401_UNAUTHORIZED

#==Database==
fake_users_db = {
    "max": {
        "id": 1,
        "username": "max",
        "full_name": "Max Osipov",
        "email": "max@example.com",
        "hashed_password": "$2a$12$g/71fmshrn191r5PCxJ15eYDvQYJk38cX360JOEV7Cayy8uC1YPG.",
        "disabled": False,
    }
}

SECRET_KEY = "secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username:str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#==Routes==
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
    )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

dir_path = os.getcwd()
storage_path = "storage"

@app.get("/", response_class=HTMLResponse)
async def read_root(token: str = Depends(oauth2_scheme)):
    return """
    <form action="/upload" enctype="multipart/form-data" method="post">
        <input name="file" type="file">
        <input type="submit">
    </form>
    """

@app.post("/upload")
async def upload_image(file: UploadFile = File(...)):
    filename, ext = os.path.splitext(file.filename)
    name = str(uuid.uuid4()) + ext
    path = os.path.join(storage_path, name)

    if os.path.exists(path):
        name = str(uuid.uuid4()) + ext
        path = os.path.join(storage_path, name)

    with open(path, "wb") as image:
        content = await file.read()
        image.write(content)
        image.close()
    return {"filename": file.filename}


@app.get("/file/{name_file}")
async def get_image(name_file: str):
    return FileResponse(os.path.join(storage_path, name_file))

@app.get("/delete/file/{name_file}")
def delete_image(name_file: str):
    try:
        os.remove(os.path.join(storage_path, name_file))
        return {"message": "removed"}
    except FileNotFoundError:
        return {"message": "error file is missing"}
