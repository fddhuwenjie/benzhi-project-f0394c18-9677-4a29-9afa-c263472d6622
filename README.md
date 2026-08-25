# 桥梁振动告警研判闭环

为桥梁结构工程师、现场检测人员和养护技术负责人提供告警接收、波形复核、风险分级、现场证据、处置批准及复测归档的一体化工作台。服务使用本地 JSON 快照与审计事件，案件通过 revision 进行并发控制。

## 构建、运行与测试

```bash
go test ./...
go run ./cmd/bridgewatch -addr=127.0.0.1:19081
go run ./cmd/bridgewatch -addr=127.0.0.1:19081 -self-check
```

也可以设置 `PORT` 环境变量指定端口。浏览器访问根路径即可打开原生工作台。JSON API 位于 `/api/alerts`、`/api/cases`、`/api/cases/{case_id}` 详情/时间线，以及 `/api/cases/{case_id}/{review|task|evidence|approve|withdraw|close}`。告警按幂等键和五分钟相似窗口去重合并，详情保留首次/当前来源与审计时间线。案件列表支持 `bridge_id`、`sensor_id`、`status`、`risk_level`、`from`、`to`、分页和 `stats=1` 统计参数；任务接口返回时限状态并支持带理由改派，证据可分批补交并校验哈希。状态变更使用 `If-Match` revision，并可通过 `Idempotency-Key` 安全重试接收和批准请求。

同桥梁传感器告警会在可配置关联窗口内保留每个测点摘要；阈值对比预览会返回绑定 revision 与摘要的确认令牌。任务超期、证据回滚、复测基线和方案变更均写入审计事件，时间线支持类型/时间范围筛选和游标分页。

批量告警会持久化批次及项级指纹，可通过 `GET /api/alerts/batches/{batch_id}` 查询并用 `POST /api/alerts/batches/{batch_id}/replay` 只重放失败项。案件详情提供风险重算历史、复核采样快照、签到轨迹、复测趋势与执行清单；`/api/cases?stats=1&group_by=bridge|sensor` 支持桥梁/传感器维度聚合统计。

阈值目录可通过 `GET /api/thresholds`（或案件列表的 `thresholds=1`）读取；复核会固定阈值快照并记录版本审计。待复核案件支持 `POST /api/cases/{case_id}/claim|release` 短期认领锁，误关联告警可用 `POST /api/cases/{case_id}/split` 拆分。任务支持逗号分隔或 `checkpoints` 数组的多测点覆盖，证据提交会校验测点归属、照片/复测跨案件冲突。处置决定到期后必须通过 `approve` 携带 `change_of_decision`、`original_decision_id` 和续期理由，关闭前会校验审计哈希链并生成归档清单。
