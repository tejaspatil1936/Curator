FROM python:3.11-slim

# No .pyc files: ./api is bind-mounted in dev, and under rootful Docker they would be root-owned.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Bake the embedding model into the image: the container never downloads a model.
ENV FASTEMBED_CACHE_PATH=/opt/fastembed
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5')"
# From here on, any Hugging Face Hub fetch fails loudly instead of downloading.
ENV HF_HUB_OFFLINE=1

COPY . .

EXPOSE 8000

# Production-shaped default. docker-compose.yml overrides this with --reload for dev.
CMD ["uvicorn", "curator.main:app", "--host", "0.0.0.0", "--port", "8000"]
