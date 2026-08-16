FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.py /app/server.py
VOLUME ["/data"]
EXPOSE 8080
CMD ["python","/app/server.py"]
