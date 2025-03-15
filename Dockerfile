FROM --platform=linux/arm64 ubuntu:latest AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang \
    git \
    gcc \
    libc6-dev \
    libpcap-dev \
    libcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 复制所有文件
COPY . .

# 设置Go环境变量
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV GO111MODULE=on

# 构建应用
RUN go build -o go-port-rocket

# 第二阶段：运行镜像
FROM --platform=linux/arm64 ubuntu:latest

# 安装运行时依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libcap2 \
    libcap2-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建非root用户
RUN groupadd -r rocket && useradd -r -g rocket -u 1500 rocket

# 复制构建好的二进制文件
COPY --from=builder /app/go-port-rocket /usr/local/bin/

# 设置capabilities
RUN setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/go-port-rocket

# 工作目录
WORKDIR /home/rocket

# 切换到非root用户
USER rocket

# 设置入口点
ENTRYPOINT ["go-port-rocket"]

# 设置默认命令
CMD ["--help"] 