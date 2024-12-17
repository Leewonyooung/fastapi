"""
author: 이원영
Description: 병원 테이블 API 핸들러
Fixed: 2024/10/7
Usage: 
"""

from fastapi import APIRouter, File, Depends, UploadFile
import os, json
import hosts,auth
from botocore.exceptions import NoCredentialsError
from botocore.exceptions import ClientError
from fastapi.responses import StreamingResponse
import io
from auth import get_current_user

router = APIRouter()

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def generate_cache_key(endpoint: str, params: dict):
    return f"{endpoint}:{json.dumps(params, sort_keys=True)}"

async def get_cached_or_fetch(cache_key, fetch_func):
    redis_client = await hosts.get_redis_connection()
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception as e:
        print(f"Redis get error: {e}")

    # Cache miss, fetch from DB
    data = await fetch_func()
    try:
        await redis_client.set(cache_key, json.dumps(data), ex=3600)
    except Exception as e:
        print(f"Redis set error: {e}")
    return data

@router.get("/delete")
async def delete(id: str = Depends(auth.get_current_user)):
    conn = hosts.connect()
    curs = conn.cursor()

    try:
        sql = "DELETE FROM image WHERE id=%s"
        curs.execute(sql, (id,))
        conn.commit()
        return {"result": "OK"}
    except Exception as e:
        print("Error:", e)
        return {"result": "Error"}
    finally:
        conn.close()

@router.post("/upload")
async def upload_file_to_s3(file: UploadFile = File(...)):
    try:
        s3_key = file.filename
        hosts.s3.upload_fileobj(file.file, hosts.BUCKET_NAME, s3_key)
        return {'result': 'OK', 's3_key': s3_key}
    except NoCredentialsError:
        return {'result': 'Error', 'message': 'AWS credentials not available.'}
    except Exception as e:
        print("Error:", e)
        return {'result': 'Error', 'message': str(e)}

@router.get("/view/{file_name}")
async def get_file(file_name: str):
    cache_key = generate_cache_key("view_file", {"file_name": file_name})

    async def fetch_file():
        file_obj = hosts.s3.get_object(Bucket=hosts.BUCKET_NAME, Key=file_name)
        file_data = file_obj['Body'].read()
        return file_data

    file_data = await get_cached_or_fetch(cache_key, fetch_file)
    if not file_data:
        return {"result": "Error", "message": "File not found in S3."}

    return StreamingResponse(io.BytesIO(file_data), media_type="image/jpeg")

@router.get('/select_clinic_name')
async def select_clinic_name(name: str, id: str = Depends(auth.get_current_user)):
    cache_key = generate_cache_key("select_clinic_name", {"name": name})

    async def fetch_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = "SELECT name FROM clinic WHERE id = %s"
                curs.execute(sql, (name,))
                rows = curs.fetchall()
            return rows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            conn.close()

    return {"results": await get_cached_or_fetch(cache_key, fetch_data)}

@router.get('/get_clinic_name')
async def get_clinic_name(name: str):
    cache_key = generate_cache_key("get_clinic_name", {"name": name})

    async def fetch_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = "SELECT id FROM clinic WHERE name = %s"
                curs.execute(sql, (name,))
                rows = curs.fetchall()
            return rows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            conn.close()

    return {"results": await get_cached_or_fetch(cache_key, fetch_data)}

@router.get('/select_search')
async def select_search(word: str = None, id: str = Depends(auth.get_current_user)):
    cache_key = generate_cache_key("select_search", {"word": word})

    async def fetch_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = "SELECT * FROM clinic WHERE name LIKE %s OR address LIKE %s"
                keyword = f"%{word}%"
                curs.execute(sql, (keyword, keyword))
                rows = curs.fetchall()
            return rows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            conn.close()

    return {"results": await get_cached_or_fetch(cache_key, fetch_data)}
# 상세화면 정보 불러오기
@router.get('/detail_clinic')
async def detail_clinic(id: str):
    cache_key = generate_cache_key("detail_clinic", {"id": id})

    async def fetch_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = "SELECT * FROM clinic WHERE id=%s"
                curs.execute(sql, (id,))
                rows = curs.fetchall()
            return rows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            conn.close()

    return {"results": await get_cached_or_fetch(cache_key, fetch_data)}

@router.get('/select_clinic')
async def select_clinic():
    cache_key = generate_cache_key("select_clinic", {})

    async def fetch_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = "SELECT * FROM clinic"
                curs.execute(sql)
                rows = curs.fetchall()
            return rows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            conn.close()

    return {"results": await get_cached_or_fetch(cache_key, fetch_data)}

@router.get("/insert")
async def insert(
    id: str = Depends(auth.get_current_user),
    name: str = None, 
    password: str = None, 
    latitude: str = None, 
    longitude: str = None, 
    starttime: str = None, 
    endtime: str = None, 
    introduction: str = None, 
    address: str = None, 
    phone: str = None, 
    image: str = None,
):
    conn = hosts.connect()
    try:
        with conn.cursor() as curs:
            sql = """
            INSERT INTO clinic
            (id, name, password, latitude, longitude, start_time, end_time, introduction, address, phone, image)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            curs.execute(sql, (id, name, password, latitude, longitude, starttime, endtime, introduction, address, phone, image))
            conn.commit()
        return {"result": "OK"}
    except Exception as e:
        print("Error:", e)
        return {"result": "Error"}
    finally:
        conn.close()

    
# edit clinic information to DB (안창빈)


@router.get("/update")
async def update(
    id: str = Depends(auth.get_current_user),
    name: str = None, 
    password: str = None, 
    latitude: str = None, 
    longitude: str = None, 
    starttime: str = None, 
    endtime: str = None, 
    introduction: str = None, 
    address: str = None, 
    phone: str = None, 
):
    cache_key = generate_cache_key("update", {"id": id})

    async def update_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = """
                UPDATE clinic
                SET name = %s,
                password = %s,
                latitude = %s,
                longitude = %s,
                start_time = %s,
                end_time = %s,
                introduction = %s,
                address = %s,
                phone = %s
                WHERE id = %s
                """
                curs.execute(sql, (name, password, latitude, longitude, starttime, endtime, introduction, address, phone, id))
                conn.commit()
            return {"result": "OK"}
        except Exception as e:
            print("Error:", e)
            return {"result": "Error"}
        finally:
            conn.close()

    return await get_cached_or_fetch(cache_key, update_data)

@router.post("/update_all")
async def update_all(
    id: str = Depends(auth.get_current_user),
    name: str = None, 
    password: str = None, 
    latitude: str = None, 
    longitude: str = None, 
    starttime: str = None, 
    endtime: str = None, 
    introduction: str = None, 
    address: str = None, 
    phone: str = None, 
    image: str = None,
):
    cache_key = generate_cache_key("update_all", {"id": id})

    async def update_data():
        conn = hosts.connect()
        try:
            with conn.cursor() as curs:
                sql = """
                UPDATE clinic
                SET name = %s,
                password = %s,
                latitude = %s,
                longitude = %s,
                start_time = %s,
                end_time = %s,
                introduction = %s,
                address = %s,
                phone = %s,
                image = %s
                WHERE id = %s
                """
                curs.execute(sql, (name, password, latitude, longitude, starttime, endtime, introduction, address, phone, image, id))
                conn.commit()
            return {"result": "OK"}
        except Exception as e:
            print("Error:", e)
            return {"result": "Error"}
        finally:
            conn.close()

    return await get_cached_or_fetch(cache_key, update_data)
