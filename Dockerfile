# 使用Ubuntu基础镜像，更稳定
FROM ubuntu:22.04

# 安装Go和其他依赖
RUN apt-get update && apt-get install -y \
    wget \
    gcc \
    libc6-dev \
    sqlite3 \
    libsqlite3-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装Go
RUN wget -O go1.21.0.linux-amd64.tar.gz https://golang.org/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# 设置工作目录
WORKDIR /app

# 复制go mod文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=1 go build -o main .

# 暴露端口
EXPOSE 8080

# 运行应用
CMD ["./main"]
