"""
author: 이원영
Description: login API with JWT
Fixed: 2024/12/11
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
import hosts,os, requests
import firebase_admin
from firebase_admin import auth
from jose.exceptions import ExpiredSignatureError
from jose import jwt, JWTError, ExpiredSignatureError
import requests
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

router = APIRouter()


SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))
# Password 암호화 설정
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
    try:
        decoded_token = auth.verify_id_token(id_token)
        print(f"Decoded Firebase Token: {decoded_token}")  # 디버깅
        return decoded_token
    except firebase_admin.exceptions.FirebaseError as e:
        print(f"Firebase token validation error: {e}")  # 디버깅
        raise ValueError(f"Invalid Firebase token: {str(e)}")

async def get_or_create_user(uid: str, email: str, name: str, picture: str):
    user_data = await select(id=email)
    print(f"User data from DB: {user_data}")  # 디버깅
    if not user_data.get("results"):
        conn = hosts.connect()
        curs = conn.cursor()
        sql = """
        INSERT INTO user (id, password, image, name, phone)
        VALUES (%s, %s, %s, %s, %s)
        """
        curs.execute(sql, (email, "", picture, name, email))
        conn.commit()
        conn.close()
        return {"id": uid, "name": name, "email": email, "image": picture}
    return user_data["results"][0]


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    try:
        to_encode = data.copy()
        expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        print(f"Created Access Token: {encoded_jwt}")  # 디버깅
        return encoded_jwt
    except Exception as e:
        print(f"Error creating JWT: {e}")  # 디버깅
        raise


def create_refresh_token(data: dict):
    """Refresh Token 생성."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(f"Created Refresh Token: {encoded_jwt}")  # 디버깅
    return encoded_jwt

@router.post("/firebase")
async def firebase_login(data: FirebaseTokenRequest):
    """Firebase 로그인 API."""
    try:
        decoded_token = verify_id_token(data.id_token)
        uid = decoded_token.get("uid")
        email = decoded_token.get("email")
        name = decoded_token.get("name")
        picture = decoded_token.get("picture")
        
        if not uid or not email:
            raise HTTPException(status_code=400, detail="Invalid Firebase token")

        user = await get_or_create_user(uid=uid, email=email, name=name, picture=picture)
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        print(user)
        access_token = create_access_token(
            data={"id": user["id"]}, expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(data={"id": user["id"]})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Firebase token validation failed: {str(e)}")

@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """일반 로그인 API."""
    user = await authenticate_user(id=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"id": user["id"]}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"id": user["id"]})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@router.post("/token/refresh")
async def refresh_token(request: RefreshTokenRequest):
    try:
        # JWT 헤더 확인 (검증 전)
        header = jwt.get_unverified_header(request.refresh_token)
        algorithm = header.get("alg", None)
        print(f"Token Header: {header}")  # 디버깅용 로그

        if not algorithm:
            raise HTTPException(status_code=401, detail="Invalid token header")

        # 알고리즘에 따라 검증
        if algorithm == "RS256":  # 애플 토큰 검증
            public_keys = requests.get("https://appleid.apple.com/auth/keys").json()["keys"]
            key = public_keys[0]  # 키 선택 (실제 kid에 맞게 찾아야 함)
            payload = jwt.decode(request.refresh_token, key, algorithms=["RS256"])
        elif algorithm == "HS256":  # 구글/내부 토큰 검증
            payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=["HS256"])
        else:
            raise HTTPException(status_code=401, detail="Unsupported token algorithm")

        # 사용자 정보 확인
        user_id: str = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # 새로운 Access Token 생성
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = create_access_token(
            data={"id": user_id}, expires_delta=access_token_expires
        )

        print(f"New Access Token: {new_access_token}")
        return {
            "access_token": new_access_token,
            "refresh_token": request.refresh_token,  # 기존 Refresh Token 반환
            "token_type": "bearer",
        }

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError as e:
        print(f"JWTError: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


async def authenticate_user(id: str, password: str):
    """사용자 인증."""
    user = await get_user(id=id, password=pwd_context.hash(password))
    if not user or not verify_password(password, user["password"]):
        return False
    return user

async def get_user(id: str, password: str):
    """DB에서 사용자 정보 조회."""
    user_data = await select(id=id)
    return user_data.get("results")[0] if user_data.get("results") else None

def verify_password(plain_password, hashed_password):
    """비밀번호 검증."""
    return pwd_context.verify(plain_password, hashed_password)

async def select(id: str = None):
    """DB에서 사용자 정보 조회."""
    conn = hosts.connect()
    curs = conn.cursor()
    curs.execute("SELECT * FROM user WHERE id=%s", (id,))
    rows = curs.fetchall()
    conn.close()
    return {"results": [{"id": row[0], "password": row[1], "image": row[2], "name": row[3], "phone": row[4]} for row in rows]}

def fetch_apple_public_keys():
    """Apple 공개 키 가져오기."""
    response = requests.get("https://appleid.apple.com/auth/keys")
    response.raise_for_status()
    return response.json()["keys"]

def construct_rsa_public_key(jwk_key):
    """JWK 키를 RSA 공개 키로 변환."""
    exponent = int.from_bytes(base64url_decode(jwk_key["e"]), "big")
    modulus = int.from_bytes(base64url_decode(jwk_key["n"]), "big")
    return RSAPublicNumbers(exponent, modulus).public_key(backend=default_backend())


def get_current_user(token: str = Depends(oauth2_scheme)):
    """JWT 유효성 검증: Apple과 Google 로그인 구분."""
    try:
        # JWT 헤더 확인 (검증 전)
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg", None)
        print(f"Token Header: {header}")  # 디버깅 로그

        if not algorithm:
            raise HTTPException(status_code=401, detail="Invalid token header")

        # 알고리즘에 따라 검증
        if algorithm == "RS256":
            # Apple 공개 키 가져오기
            apple_keys = fetch_apple_public_keys()
            kid = header["kid"]
            matching_key = next((key for key in apple_keys if key["kid"] == kid), None)
            if not matching_key:
                raise HTTPException(status_code=401, detail="No matching public key found")

            public_key = construct_rsa_public_key(matching_key)
            payload = jwt.decode(token, public_key, algorithms=["RS256"], issuer="https://appleid.apple.com")

        elif algorithm == "HS256":
            # 구글 로그인 또는 내부 검증
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        else:
            raise HTTPException(status_code=401, detail="Unsupported token algorithm")

        # 사용자 ID 확인
        user_id: str = payload.get("id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return user_id

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError as e:
        print(f"JWTError: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Unexpected Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from jose import JWTError, jwt
import requests


class AppleToken(BaseModel):
    identity_token: str

@router.post("/apple")
def apple_login(token: AppleToken):
    # Apple Public Keys 가져오기
    apple_public_keys = requests.get("https://appleid.apple.com/auth/keys").json()
    
    # Apple Identity Token 검증
    try:
        payload = jwt.decode(
            token.identity_token,
            apple_public_keys,
            algorithms=["RS256"],
            audience="com.thejoeun2jo.vetApp",  # Apple Developer에서 설정한 Bundle ID
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid Apple Identity Token")

    # 사용자 정보 추출
    user_id = payload["sub"]  # Apple 고유 사용자 ID

    # Access Token 생성
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"id": user_id}, expires_delta=access_token_expires)

    # Refresh Token 생성
    refresh_token = create_refresh_token(data={"id": user_id})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

