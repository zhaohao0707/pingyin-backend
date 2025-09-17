# 多阶段构建 - 构建阶段
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

# 安装构建依赖
RUN apk add --no-cache gcc musl-dev sqlite-dev

# 设置工作目录
WORKDIR /app

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 设置交叉编译环境变量
ARG TARGETOS
ARG TARGETARCH

# 构建应用 (启用CGO以支持SQLite)
RUN CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -a -ldflags '-linkmode external -extldflags "-static"' -o main .

# 运行阶段 - 使用轻量级基础镜像
FROM alpine:latest

# 安装运行时依赖
RUN apk add --no-cache ca-certificates sqlite

# 创建非root用户
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# 设置工作目录
WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/main .

# 创建数据目录并设置权限
RUN mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# 切换到非root用户
USER appuser

# 设置环境变量
ENV DATABASE_PATH=/app/data/pinyin.db
ENV GIN_MODE=release

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/words || exit 1

# 运行应用
CMD ["./main"]
