#!/bin/bash
echo "🔧 启动Go后端服务..."
go run . 2>&1 | tee ../backend.log
