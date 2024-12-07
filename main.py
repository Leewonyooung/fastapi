"""
author: 
Description: 
Fixed: 
Usage: 
"""

from fastapi import FastAPI
from clinic import router as clinic_router
from favorite import router as favorite_router
from user import router as user_router
from pet import router as pet_router
from available_time import router as available_router
from species import router as species_router 
from reservation import router as reservation_router
from myprofile import mypage_router
import pymysql, hosts
import os

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
BUCKET_NAME = os.getenv('AWS_S3_BUCKET_NAME')
REGION = os.getenv('AWS_REGION')
VET_DB = os.getenv('VET_DB')
VET_USER = os.getenv('VET_DB_USER')
VET_PASSWORD = os.getenv('VET_DB_PASSWORD')
VET_TABLE = os.getenv('VET_DB_TABLE')
VET_PORT = os.getenv("VET_DB_PORT")


def connect():
    conn = pymysql.connect(
        host=hosts.vet_academy,
        user='root',
        password='qwer1234',
        charset='utf8',
        db='veterinarian',
        port=32176
    )
    return conn

app = FastAPI()
app.include_router(clinic_router, prefix="/clinic", tags=["clinic"])
app.include_router(favorite_router, prefix="/favorite", tags=["favorite"])
app.include_router(user_router, prefix="/user", tags=["user"])
app.include_router(pet_router, prefix="/pet", tags=["pet"])
app.include_router(mypage_router, prefix="/mypage", tags=["mypage"])
app.include_router(available_router, prefix="/available", tags=["available"])
app.include_router(species_router, prefix="/species", tags=["species"])
app.include_router(reservation_router, prefix="/reservation", tags=["reservation"])



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host = "0.0.0.0", port = 8000)