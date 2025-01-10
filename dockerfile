FROM python:3.12-slim

# Rust 설치를 위한 패키지 관리 도구 설치
RUN apt-get update && apt-get install -y \
    curl build-essential libssl-dev && \
    curl https://sh.rustup.rs -sSf | bash -s -- -y && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 작업 디렉터리 설정
WORKDIR /fastapi

# 프로젝트 파일 복사
COPY . .

# Rust 경로 설정 및 의존성 설치
ENV PATH="/root/.cargo/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# 포트 노출
EXPOSE 6004

# 애플리케이션 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "6004"]
