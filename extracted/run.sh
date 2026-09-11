#!/usr/bin/env bash
# 运行快手纯算 Docker 容器（纯 docker run，无需 compose）
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-kuaishou-pure-sign}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-kuaishou-sign}"
HOST_PORT="${HOST_PORT:-8000}"

# 停止并删除同名旧容器（若存在）
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "启动容器: ${CONTAINER_NAME}  端口: ${HOST_PORT}->8000"

docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  -p "${HOST_PORT}:8000" \
  # 如需自定义状态，可在此传入环境变量，例如：
  # -e SIG3_COUNTER=100 \
  # -e ATLAS64_COUNTER=100 \
  # -e KAW_SEQ_START=100 \
  "${IMAGE_NAME}:${IMAGE_TAG}"

sleep 2
echo "健康检查: http://127.0.0.1:${HOST_PORT}/ping"
curl -s "http://127.0.0.1:${HOST_PORT}/ping" || true
echo
echo "查看日志: docker logs -f ${CONTAINER_NAME}"
