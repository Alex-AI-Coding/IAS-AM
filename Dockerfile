FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QT_QPA_PLATFORM=offscreen

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY antivirus ./antivirus
COPY tests ./tests
COPY main.py README.md ./

RUN mkdir -p /app/antivirus_data

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "antivirus.api", "run", "--host", "0.0.0.0", "--port", "5000"]
