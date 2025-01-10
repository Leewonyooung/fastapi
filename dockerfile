# Python 3.12-slim 기반 이미지
FROM python:3.12-slim

# 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    curl build-essential libssl-dev gcc \
    postgresql-client postgresql-server-dev-all && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /postgre

# pip, setuptools, wheel 최신화
RUN pip install --upgrade pip setuptools wheel

# 프로젝트 파일 복사
COPY . .

# 모든 패키지 설치 및 최신 버전으로 업데이트
RUN pip install --no-cache-dir -r postgre/requirements.txt && \
    pip install --no-cache-dir --upgrade $(pip freeze | cut -d'=' -f1)

# 포트 노출
EXPOSE 6004

# 애플리케이션 실행
CMD ["uvicorn", "postgre.main:app", "--host", "0.0.0.0", "--port", "6004"]
