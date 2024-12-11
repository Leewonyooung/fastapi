import pymysql
import os, json, io
import boto3
from botocore.exceptions import NoCredentialsError
import firebase_admin
from firebase_admin import credentials, initialize_app

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
BUCKET_NAME = os.getenv('AWS_S3_BUCKET_NAME')
REGION = os.getenv('AWS_REGION')
VET_DB = os.getenv('VET_DB')
VET_USER = os.getenv('VET_DB_USER')
VET_PASSWORD = os.getenv('VET_DB_PASSWORD')
VET_TABLE = os.getenv('VET_DB_TABLE')
VET_FIREBASE_KEY = os.getenv('VET_FIREBASE_KEY')

s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)


# 환경 변수에서 Firebase 키를 가져오기
firebase_key_json = os.getenv("VET_FIREBASE_KEY")
if not firebase_key_json:
    raise ValueError("VET_FIREBASE_KEY environment variable is not set")

# JSON 문자열을 메모리 파일로 변환
firebase_key = io.StringIO(firebase_key_json)

# Firebase 초기화
cred = credentials.Certificate(firebase_key)
initialize_app(cred)


def connect():
    conn = pymysql.connect(
        host=VET_DB,
        user=VET_USER,
        password=VET_PASSWORD,
        charset='utf8',
        db=VET_DB,
        port=32176
    )
    return conn