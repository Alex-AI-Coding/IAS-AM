FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QT_QPA_PLATFORM=offscreen

WORKDIR /app

# Qt workflow tests run offscreen but still load these native runtime libraries.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libgl1 libegl1 libopengl0 libxkbcommon0 libglib2.0-0 \
       libdbus-1-3 libfontconfig1 libx11-6 libstdc++6 libzstd1 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY antivirus ./antivirus
COPY tests ./tests
COPY main.py README.md .flake8 ./
COPY scripts ./scripts
COPY demo_samples ./demo_samples

RUN mkdir -p /app/antivirus_data

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "antivirus.api", "run", "--host", "0.0.0.0", "--port", "5000"]
