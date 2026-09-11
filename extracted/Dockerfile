# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ---- 依赖层 ----
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# ---- 应用层 ----
# 目录结构必须保持：/app 下包含 kaw/ demo/ wb_*.bin
COPY kaw/ /app/kaw/
COPY demo/ /app/demo/
COPY wb_round_tables.bin /app/wb_round_tables.bin
COPY wb_final_tables.bin /app/wb_final_tables.bin

# 非 root 用户运行
RUN useradd -r -u 1000 -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/ping',timeout=3).read()==b'\"pong\"' else 1)" || exit 1

CMD ["python", "-m", "uvicorn", "demo.index:app", "--host", "0.0.0.0", "--port", "8000"]
