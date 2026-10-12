FROM python:3.12-slim
WORKDIR /app
ENV HOST=0.0.0.0
ENV PORT=8000
COPY . /app
EXPOSE 8000
CMD ["python", "server.py"]
