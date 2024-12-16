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
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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
        print(f"Received Refresh Token: {request.refresh_token}")  # 디버깅 로그
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"Decoded Payload: {payload}")  # 디버깅 로그

        user_id: str = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

    except JWTError as e:
        print(f"JWTError: {e}")  # 디버깅 로그
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    new_access_token = create_access_token(
        data={"id": user_id}, expires_delta=access_token_expires
    )

    print(f"New Access Token: {new_access_token}")  # 디버깅 로그
    return {
        "access_token": new_access_token,
        "refresh_token": request.refresh_token,  # 기존 Refresh Token 반환
        "token_type": "bearer",
    }


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

def get_current_user(token: str = Depends(oauth2_scheme)):
    """JWT 유효성 검증."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

class AppleLoginRequest(BaseModel):
    id_token: str
    user_identifier: str
    email: Optional[str]  # Optional로 수정

@router.post("/apple")
async def apple_login(request: AppleLoginRequest):
    """Apple 로그인 API."""
    try:
        # Apple ID Token 검증
        decoded_token = verify_apple_identity_token(request.id_token)
        print(f"decoded : {decoded_token}")
        user_identifier = decoded_token.get("sub")  # Apple의 고유 사용자 ID
        email = request.email or decoded_token.get("email")
        name = decoded_token.get("name", "Apple User")
        picture = decoded_token.get("picture", "")  # Apple은 기본적으로 프로필 이미지를 제공하지 않음

        if not user_identifier or not email:
            raise HTTPException(status_code=400, detail="Invalid Apple token")

        # 데이터베이스에 사용자 생성 또는 조회
        user = await get_or_create_user(
            uid=user_identifier, email=email, name=name, picture=picture
        )

        # Access Token 및 Refresh Token 생성
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
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
        raise HTTPException(status_code=401, detail=f"Apple token validation failed: {str(e)}")
    except Exception as e:
        print(f"Error during Apple login: {e}")  # 디버깅 로그
        raise HTTPException(status_code=500, detail="Internal Server Error")

def verify_apple_identity_token(id_token: str):
    keys = get_apple_public_keys()
    header = jwt.get_unverified_header(id_token)
    print("Token Header (kid):", header.get("kid"))
    print("Available Apple Public Keys:", [key["kid"] for key in keys])

    key = next((k for k in keys if k["kid"] == header.get("kid")), None)
    if not key:
        print(f"No matching key found for kid: {header.get('kid')}")
        raise ValueError("Invalid Apple ID token key")




def get_apple_public_keys():
    """Apple 공개 키 가져오기."""
    try:
        response = requests.get("https://appleid.apple.com/auth/keys", timeout=5)
        response.raise_for_status()
        keys = response.json().get("keys", [])
        if not keys:
            raise ValueError("Apple public keys are missing")
        return keys
    except requests.RequestException as e:
        print(f"Error fetching Apple public keys: {e}")  # 디버깅 로그
        raise ValueError("Failed to fetch Apple public keys")
