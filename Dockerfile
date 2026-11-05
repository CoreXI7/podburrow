# Podburrow: python 3.12 alpine + mutagen for tags, hash-checked.
FROM python:3.15-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
COPY app /app
COPY tools /tools
USER 1000:1000
CMD ["python3", "-u", "/app/server.py"]
