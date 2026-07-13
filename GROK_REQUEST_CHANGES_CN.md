# Grok 免费 OAuth 请求链路改动说明

本文记录 CLIProxyAPI 对 Grok 4.5 免费 OAuth 账号请求链路的适配。文档不包含测试账号、访问令牌、刷新令牌或其他凭证信息。

## 背景

测试发现，同一个普通 xAI OAuth 账号存在两种不同结果：

- 使用 OAuth 令牌直接请求 `https://api.x.ai/v1` 时，上游按常规 API 计费通道处理，并返回消费额度相关的 HTTP 402。
- 官方 Grok Agent 使用的推理代理能够识别该账号。请求 `grok-4.5` 并带上 Grok CLI 协议头后，可以正常返回结果，实际响应模型为 `grok-4.5-build-free`。

原有执行器直接采用凭证中的 `base_url`。普通 OAuth 凭证通常保存的是 `https://api.x.ai/v1`，因此免费账号被错误地发送到了 API Key/付费 API 通道。同时，请求缺少 Grok CLI 推理代理要求的客户端标识与模型覆盖请求头。

xAI 官方网络说明也将 `cli-chat-proxy.grok.com` 描述为推理代理，而 `api.x.ai` 用于直接 API 访问：<https://docs.x.ai/build/enterprise>。

## 新的路由规则

| 凭证类型 | Base URL 状态 | 实际请求地址 | Grok CLI 请求头 |
| --- | --- | --- | --- |
| OAuth 或 Grok CLI 会话 | 空或默认 `api.x.ai/v1` | `https://cli-chat-proxy.grok.com/v1` | 添加 |
| OAuth 或 Grok CLI 会话 | 显式自定义地址 | 保留自定义地址 | 添加 |
| API Key | 空或默认地址 | `https://api.x.ai/v1` | 不添加 |
| API Key | 显式自定义地址 | 保留自定义地址 | 不添加 |

因此，外部客户端仍然只需请求模型 `grok-4.5`。免费 OAuth 账号会自动进入免费推理通道，而 API Key 账号的原有行为保持不变。

## 协议请求头

OAuth 与 Grok CLI 会话请求会增加以下请求头：

- `X-XAI-Token-Auth: xai-grok-cli`
- `x-grok-client-version: 0.2.93`
- `User-Agent: xai-grok-workspace/0.2.93`
- `x-grok-model-override: <请求模型>`
- `x-grok-client-identifier: <客户端标识>`，仅在凭证元数据提供标识时添加

`Authorization: Bearer <OAuth token>` 继续由原有逻辑设置。模型覆盖值会先去除 CLIProxyAPI 的思考强度后缀，例如 `grok-4.5(high)` 会发送为 `grok-4.5`。

客户端版本默认使用 `0.2.93`，也可以通过凭证元数据中的 `grok_cli_version`、`grok_version` 或 `x_grok_client_version` 覆盖。

## 代码改动

### `internal/runtime/executor/xai_executor.go`

- 增加 Grok CLI 推理代理地址、默认客户端版本和 User-Agent 常量。
- 增加 `xaiRequestCreds`，集中完成 OAuth/API Key 请求地址选择。
- 增加 `xaiUsesGrokCLIProxy` 与 `xaiShouldUseGrokCLIProxyBaseURL`，避免覆盖用户显式配置的自定义地址。
- 增加 Grok CLI 会话识别、元数据读取、版本选择及模型覆盖处理。
- 增加 `applyXAIGrokCLIProxyHeaders`，统一添加推理代理请求头。
- Responses、Compact、流式 Responses、图片和视频执行路径统一使用新的凭证路由函数。
- `PrepareRequest` 和内部 HTTP 请求使用相同的 Grok CLI 请求头逻辑。
- Grok CLI 会话过期时不再错误使用普通 OAuth 刷新流程，而是返回重新登录并导入凭证的提示。

### `internal/runtime/executor/xai_websockets_executor.go`

- WebSocket 请求与 HTTP 请求共用 `xaiRequestCreds` 路由规则。
- WebSocket 握手同步携带 Grok CLI 客户端头和模型覆盖值。

### `internal/runtime/executor/xai_executor_test.go`

增加或更新了以下测试：

- Grok CLI 会话的代理地址、Bearer 令牌和客户端请求头。
- 普通 OAuth 凭证从默认 API 地址切换到 CLI 推理代理。
- API Key 凭证继续使用 `api.x.ai/v1`。
- `grok-4.5(high)` 的模型覆盖值规范化为 `grok-4.5`。
- Grok CLI 会话不进入普通 OAuth 刷新流程。
- 原有会话 ID 请求头测试适配新的函数参数。

## 请求流程

```text
外部客户端请求 model=grok-4.5
              |
              v
CLIProxyAPI 选择 xAI 凭证
              |
              +-- OAuth/CLI 会话 --> cli-chat-proxy.grok.com/v1
              |                       + Grok CLI 请求头
              |
              +-- API Key ----------> api.x.ai/v1
                                      + 标准 xAI API 请求头
```

## 验证结果

使用普通免费 OAuth 账号和本地 HTTP 代理完成了实际链路验证：

- `GET /v1/models` 能列出 `grok-4.5`。
- `POST /v1/responses` 返回 HTTP 200，状态为 `completed`。
- `POST /v1/chat/completions` 返回 HTTP 200，结束原因为 `stop`。
- 两个接口的上游响应模型均为 `grok-4.5-build-free`。
- 定向 xAI executor 单元测试通过。
- Go 1.26.5 下执行 `go build -o test-output ./cmd/server` 编译通过。
- `git diff --check` 通过。

## 兼容性与维护提示

- 免费模型的上游名称 `grok-4.5-build-free` 是服务端返回值；外部请求仍应使用 `grok-4.5`。
- Grok CLI 协议和客户端版本可能继续变化。如果上游再次拒绝请求，应优先核对官方客户端版本、User-Agent 和新增请求头。
- 显式自定义 Base URL 会被保留，便于测试服务器或兼容代理使用。
- API Key 凭证不会被切换到免费 OAuth 通道。
- 图片和视频路径目前也共用凭证地址选择；这些能力是否向免费账号开放仍由上游决定。

## 隐私与配置

- 代码、测试和本文档均未写入真实账号或令牌。
- 实测使用的凭证、临时管理密钥、API Key、日志、管理面板缓存和运行二进制已在测试结束后清除。
- 项目没有新增正式 `config.yaml`，`config.example.yaml` 保持仓库默认内容。
