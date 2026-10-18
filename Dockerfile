FROM python:3.12-slim
WORKDIR /app
ENV HOST=0.0.0.0
ENV PORT=8000
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY . /app
EXPOSE 8000
CMD ["python", "server.py"]
