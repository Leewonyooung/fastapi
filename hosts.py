import pymysql
import os
import boto3
from botocore.exceptions import NoCredentialsError
import firebase_admin
from firebase_admin import credentials, auth


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


firebase_key_json = os.getenv("FIREBASE_KEY")
with open("serviceAccountKey.json", "w") as f:
    f.write(firebase_key_json)
# Firebase Admin SDK 초기화
cred = credentials.Certificate(VET_FIREBASE_KEY)
firebase_admin.initialize_app(cred)



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