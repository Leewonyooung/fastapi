"""
author: 이원영
Description: login API with JWT
Fixed: 2024/10/7
Usage: 로그인시 JWT 토큰 인증절차를 통한 보안성 확보
"""
from datetime import datetime, timedelta
from fastapi import APIRouter
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import hosts,os
import firebase_admin
from firebase_admin import credentials, auth
router = APIRouter()


SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES')
REFRESH_TOKEN_EXPIRE_DAYS = os.getenv('REFRESH_TOKEN_EXPIRE_DAYS')

# Password 암호화
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/auth/firebase",
    description="Paste your Firebase or Social Login Token here.",
)

class RefreshTokenRequest(BaseModel):
    refresh_token: str


class FirebaseTokenRequest(BaseModel):
    id_token: str


def verify_id_token(id_token: str):
    """
    Firebase ID 토큰을 검증하고 디코딩된 사용자 정보를 반환.
    """
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except firebase_admin.exceptions.FirebaseError as e:
        raise ValueError(f"Invalid Firebase token: {str(e)}")


async def get_or_create_user(uid: str, email: str, name: str, picture: str):
    # DB에서 사용자 확인
    user_data = await select(id=email)
    if not user_data.get("results"):
        # 신규 사용자 등록
        conn = hosts.connect()
        curs = conn.cursor()
        sql = """
        INSERT INTO user (id, password, image, name, phone)
        VALUES (%s, %s, %s, %s, %s)
        """
        # Firebase에서는 비밀번호를 사용하지 않음
        curs.execute(sql, (email, "", picture, name, email))
        conn.commit()
        conn.close()
        return {"id": uid, "name": name, "email": email, "image": picture}
    return user_data["results"][0]

import os
from datetime import timedelta

# 환경 변수에서 ACCESS_TOKEN_EXPIRE_MINUTES를 읽어 정수형으로 변환
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))

@router.post("/auth/firebase")
async def firebase_login(data: FirebaseTokenRequest):
    try:
        # Firebase ID 토큰 검증
        decoded_token = verify_id_token(data.id_token)
        uid = decoded_token.get("uid")
        email = decoded_token.get("email")
        name = decoded_token.get("name")
        picture = decoded_token.get("picture")
        if not uid:
            raise HTTPException(status_code=400, detail="Invalid Firebase token")

        # 사용자 생성 또는 가져오기
        user = await get_or_create_user(uid=uid, email=email, name=name, picture=picture)

        # JWT 토큰 생성
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"id": user["id"]}, expires_delta=access_token_expires
        )

        return {"access_token": access_token, "token_type": "bearer"}

    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Firebase token validation failed: {str(e)}")



def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def get_user(id: str, password: str):
    user_data = await select(id=id) 
    results = user_data.get("results")
    if results:
        return results[0]  
    return None

async def authenticate_user(id: str, password: str):
    user = await get_user(id=id, password=pwd_context.hash(password))
    if not user or not verify_password(password, user["password"]):  # 딕셔너리 접근
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def select(id: str = None):
    conn = hosts.connect()
    curs = conn.cursor()
    sql = "SELECT * FROM user WHERE id=%s"
    curs.execute(sql, (id))
    rows = curs.fetchall()
    conn.close()
    result = [
        {"id": row[0], "password": row[1], "image": row[2], "name": row[3], "phone": row[4]}
        for row in rows
    ]
    return {"results": result}

# JWT 유효성 검증
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")



@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(id=form_data.username, password=form_data.password)  # await 추가
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # access_token = create_access_token(data={"id": user["id"]})
    access_token = create_access_token(
        data={"id": user["id"], "password":user['password']}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token( data={"id": user["id"], "password":user['password']})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

# refreshToken으로 새로운 accessToken 발급
@router.post("/token/refresh")
async def refresh_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # 새 accessToken 발급
    new_access_token = create_access_token(data={"id": user_id})
    return {"access_token": new_access_token, "token_type": "bearer"}