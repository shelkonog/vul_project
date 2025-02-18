FROM python:3.11.11-bookworm

# Установка пакетов для проекта
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app

# Копирование проекта
COPY . .

# Настройка записи и доступа
RUN chmod -R 777 ./
