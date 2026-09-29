FROM python:3.12-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py config.py ./
CMD ["python", "/lab/agent.py"]
