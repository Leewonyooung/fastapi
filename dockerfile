FROM python:3.12-slim
WORKDIR /fastapi
COPY ./fastapi ./fastapi
WORKDIR /fastapi/fastapi
COPY ./fastapi/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 6004

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "6004"]
