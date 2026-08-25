# BENZHI_README

## 项目说明
- 项目：benzhi-project-f0394c18-9677-4a29-9afa-c263472d6622
- 项目用途：桥梁振动告警研判闭环提供从传感器告警接收、波形复核、风险分级、现场证据提交、处置批准到复测关闭归档的中文浏览器工作台和 JSON API。
- Go 工具链：`golang:1.22`
- 前端工具链：原生 HTML、CSS 和 JavaScript，由 Go 服务直接提供

## 项目描述
- 项目名称：桥梁振动告警研判闭环
- 项目概述：为结构工程团队提供桥梁振动告警的采集、研判、现场核验、处置批准和效果验证一体化工作台，所有状态变化可追溯并支持复核。
- 核心工作流：振动告警进入系统后完成信号复核与风险分级，形成待核验案件；检测人员提交现场证据，负责人批准处置建议，验证振动恢复后归档关闭。
- 对外接口：由 Go 服务提供原生 HTML、CSS 和 JavaScript 的浏览器工作台，页面支持告警列表、波形复核、现场证据上传、处置批准和关闭归档，并通过 JSON HTTP API 交互。

## 标准构建、运行和测试命令
进入容器后执行：
cd '/app' && GOTOOLCHAIN=local go build ./...
cd /app && GOTOOLCHAIN=local go run ./cmd/bridgewatch -addr=127.0.0.1:19081 -self-check
cd '/app' && GOTOOLCHAIN=local go test ./...

## Docker 构建和进入容器
chmod +x build_benzhi_docker.sh
./build_benzhi_docker.sh benzhi-project-f0394c18-9677-4a29-9afa-c263472d6622-amd64 linux/amd64
./build_benzhi_docker.sh benzhi-project-f0394c18-9677-4a29-9afa-c263472d6622-arm64 linux/arm64
docker run -it benzhi-project-f0394c18-9677-4a29-9afa-c263472d6622-amd64:latest

## 题目验证命令
1. 预期退出码 0：`go test ./...`
2. 预期退出码 0：`go run ./cmd/bridgewatch -addr=127.0.0.1:19081 -self-check`
