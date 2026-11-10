FROM python:3.12-slim

WORKDIR /app

# Шаардлагатай сангуудыг суулгах
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Кодыг хуулах
COPY . .

# Өгөгдлийн санг бэлтгэх
RUN python -c "import database; database.init_db()"

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
