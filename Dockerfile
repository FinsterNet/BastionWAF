FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies and install
COPY waf/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy WAF code
COPY waf/ /app/waf/

WORKDIR /app/waf

ENV PYTHONUNBUFFERED=1
ENV BASTION_HOST=0.0.0.0

EXPOSE 8080 8000

CMD ["python", "main.py"]
