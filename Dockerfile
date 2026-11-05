# Podburrow: python 3.12 alpine + mutagen for tags, hash-checked.
FROM python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY app /app
COPY tools /tools
USER 1000:1000
CMD ["python3", "-u", "/app/server.py"]
