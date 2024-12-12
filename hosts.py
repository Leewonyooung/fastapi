import pymysql
import os, json
import boto3
from redis.asyncio import Redis  # 올바른 클래스 임포트
from firebase_admin import credentials, initialize_app

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
BUCKET_NAME = os.getenv('AWS_S3_BUCKET_NAME')
REGION = os.getenv('AWS_REGION')
VET_DB = os.getenv('VET_DB')
VET_USER = os.getenv('VET_DB_USER')
VET_PASSWORD = os.getenv('VET_DB_PASSWORD')
VET_TABLE = os.getenv('VET_DB_TABLE')
VET_PORT = os.getenv('VET_PORT')
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.getenv("REDIS_PORT")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")



s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=REGION
)


firebase_key_json = os.getenv("VET_FIREBASE_KEY")
if not firebase_key_json:
    raise ValueError("VET_FIREBASE_KEY environment variable is not set")

# JSON 문자열을 Python 딕셔너리로 변환
firebase_key = json.loads(firebase_key_json)

# Firebase 초기화
cred = credentials.Certificate(firebase_key)
print(cred)
initialize_app(cred)


redis_client = None

async def get_redis_connection():
    global redis_client
    if not redis_client:
        try:
            print("Initializing Redis connection...")
            # Redis 클라이언트 생성
            redis_client = Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                # password=REDIS_PASSWORD,
                decode_responses=True  # 문자열 디코딩 활성화
            )
            # 연결 테스트
            await redis_client.ping()
            print("Redis connection established.")
        except Exception as e:
            print(f"Failed to connect to Redis: {e}")
            redis_client = None
            raise e
    return redis_client


def connect():
    conn = pymysql.connect(
        host=VET_DB,
        user=VET_USER,
        password=VET_PASSWORD,
        charset='utf8',
        db=VET_TABLE,
        port=int(VET_PORT)
    )
    return conn