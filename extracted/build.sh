#!/usr/bin/env bash
# 构建快手纯算 Docker 镜像
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-kuaishou-pure-sign}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DOCKERFILE="${DOCKERFILE:-Dockerfile}"

echo "[1/2] 构建上下文目录: $(pwd)"
echo "[2/2] 构建镜像: ${IMAGE_NAME}:${IMAGE_TAG}"

docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -f "${DOCKERFILE}" .

echo "构建完成: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "运行: ./run.sh"
