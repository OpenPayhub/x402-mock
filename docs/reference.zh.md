# API 参考

x402-mock 模块的完整 API 文档。

## Servers

**HTTP 402 支付协议服务端实现**

Servers 模块提供了一个基于 FastAPI 的服务器框架，用于实现 HTTP 402 Payment Required 协议。它采用事件驱动架构，封装了所有支付收款逻辑，使支付接收方能够以最少的配置集成 web3 支付接受功能。

**主要特性：**
- **FastAPI 集成**：扩展的 FastAPI 应用程序，内置支付端点路由
- **令牌管理**：安全的 HMAC 签名访问令牌生成和验证
- **事件驱动架构**：订阅支付生命周期事件（请求、验证、结算）
- **多链支持**：在不同区块链网络上注册多种支付方式
- **自动结算**：验证成功后可选自动链上结算
- **安全工具**：私钥生成、令牌签名和环境密钥管理
- **现代 EVM 签名**：
  - **USDC**：ERC-3009 (`transferWithAuthorization`)
  - **通用 ERC20**：Permit2 (`permitTransferFrom`)

**主要组件：**
- `Http402Server`：扩展 FastAPI 并支持支付协议的主要服务器类
- Api key相关工具：`generate_token()`、`verify_token()`、`create_private_key()`、`save_key_to_env()`

::: x402_mock.servers

## Clients

**HTTP 402 支付客户端中间件**

Clients 模块提供了一个智能 HTTP 客户端，能够透明地处理 HTTP 402 Payment Required 响应。它扩展了 `httpx.AsyncClient`，自动拦截支付挑战、生成签名的支付许可、将其交换为访问令牌并重试原始请求——所有这些都不需要用户显式干预。

**主要特性：**
- **透明支付处理**：自动处理 402 响应，无需手动干预
- **httpx 兼容性**：完全兼容的 httpx.AsyncClient 直接替代品
- **离线签名自动签名**：使用注册的支付方法生成链/代币特定的离线授权（ERC-3009 / Permit2）
- **令牌交换**：自动在服务器端点将许可交换为访问令牌
- **请求重试**：无缝重试获得授权后的原始请求
- **多链支持**：在不同区块链网络上注册支付能力

**主要组件：**
- `Http402Client`：具有自动支付流程处理功能的扩展异步 HTTP 客户端

**使用模式：**
1. 初始化客户端并注册支付方法
2. 向受保护资源发出标准 HTTP 请求
3. 客户端自动处理 402 挑战并获取访问权限
4. 透明地接收成功响应

::: x402_mock.clients

## Adapters

**统一区块链适配器接口**

Adapters 模块提供了一个统一的抽象层，弥合了各种区块链平台（EVM、Solana 等）之间的差异。它实现了基于插件的架构，具有自动区块链类型检测功能，能够在异构区块链生态系统中实现一致的支付许可签名、签名验证和链上结算操作。

**主要特性：**
- **区块链抽象**：EVM、SVM（Solana）和其他区块链平台的统一接口
- **自动类型检测**：从链标识符（CAIP-2 格式）识别区块链类型
- **签名操作**：生成和验证区块链特定的加密签名
- **授权验证**：验证授权真实性、过期时间、随机数和链上条件
- **交易结算**：执行链上转账并跟踪确认（EVM 上的 ERC-3009 / Permit2）
- **余额查询**：查询不同链上的代币余额和授权额度
- **可扩展架构**：工厂模式便于轻松添加新的区块链适配器

**主要组件：**
- `AdapterHub`：将操作路由到适当区块链适配器的中央网关
- `AdapterFactory`：定义适配器接口契约的抽象基类
- `PaymentRegistry`：管理支付方法注册和检索
- 平台特定适配器：`EVMAdapter`（以太坊/EVM 链）、SVM 适配器（即将推出）

**架构模式：**
使用适配器模式结合工厂模式，提供一致的 API，同时在底层委托给区块链特定的实现。

::: x402_mock.adapters

## EVM

**以太坊虚拟机（EVM）区块链适配器**

EVM 模块提供了针对以太坊虚拟机兼容区块链的专用适配器实现。它包含了处理 EVM 链上支付授权、签名验证、交易结算和链配置管理的完整工具集。

**主要特性：**
- **ERC-3009 支持**：USDC 和其他兼容代币的 `transferWithAuthorization` 离线签名
- **Permit2 支持**：通用 ERC-20 代币的 `permitTransferFrom` 离线授权
- **多链配置管理**：统一的链配置和资产信息管理
- **智能合约交互**：完整的 ERC-20、ERC-3009 和 Permit2 ABI 定义
- **签名验证**：链上和链下的签名验证机制
- **配置工具**：从外部源获取链信息和代币列表的实用工具

**主要组件：**
- `EVMAdapter`：主要的 EVM 区块链适配器类
- `EVMRegistry`：EVM 支付方法注册表
- `EVMECDSASignature`、`EVMTokenPermit`、`ERC3009Authorization`、`Permit2Signature`：签名和授权数据结构
- `EVMVerificationResult`、`EVMTransactionConfirmation`：验证和交易结果模型

**配置管理工具：**

**EvmPublicRpcFromChainList**

实时从 [Chainlist.org](https://chainlist.org) 拉取公共 RPC 端点。支持按协议（`https` / `wss`）和隐私等级（`none` / `limited`）过滤，帮助你快速为任意 EVM 链找到可用的无需 API Key 的 RPC 地址。

```python
from x402_mock.adapters.evm import EvmPublicRpcFromChainList

rpc = EvmPublicRpcFromChainList()

# 直接获取一个可用的公共 HTTPS RPC
print(rpc.pick_public_rpc("eip155:1"))

# 只要无隐私跟踪的节点
print(rpc.pick_public_rpc("eip155:8453", tracking_type="none"))
```

**EvmTokenListFromUniswap**

从 [Uniswap 官方代币列表](https://tokens.uniswap.org) 查询任意代币的合约地址和精度（decimals）。结果会自动缓存，避免重复请求网络。

```python
from x402_mock.adapters.evm import EvmTokenListFromUniswap

tokens = EvmTokenListFromUniswap()

# 查询以太坊主网 USDC 的合约地址和精度
address, decimals = tokens.get_token_address_and_decimals("eip155:1", "USDC")
print(address, decimals)
```

**EvmChainInfoFromEthereumLists**

从 [ethereum-lists](https://github.com/ethereum-lists/chains) 仓库获取权威链元数据，**专门用于解析 Infura / Alchemy 的带 API Key 占位符的 RPC 模板**，以及枚举无需密钥的公共 RPC 列表。

```python
from x402_mock.adapters.evm import EvmChainInfoFromEthereumLists

chain = EvmChainInfoFromEthereumLists()

# 获取 Infura / Alchemy RPC 模板（含 {API_KEY} 占位符）
print(chain.get_infura_rpc_url("eip155:1"))
print(chain.get_alchemy_rpc_url("eip155:1"))

# 列出所有无需 API Key 的公共端点
print(chain.get_public_rpc_urls("eip155:137"))
```

**其他实用函数：**

- `get_private_key_from_env()`：从环境变量加载 EVM 服务器私钥
- `get_rpc_key_from_env()`：从环境变量加载 EVM 基础设施 API 密钥
- `amount_to_value()` / `value_to_amount()`：代币金额与链上最小单位之间的互转
- `parse_caip2_eip155_chain_id()`：将 CAIP-2 标识符解析为整数链 ID
- `fetch_erc20_name_version_decimals()`：从链上 RPC 读取代币名称、版本和精度

::: x402_mock.adapters.evm

## Schemas

**基础模式模型和类型系统**

Schemas 模块定义了支撑整个 x402_mock 框架的基础类型系统和数据模型。它提供了符合 RFC8785 的 Pydantic 模型用于加密操作、确保跨区块链实现类型安全的抽象基类，以及标准化的 HTTP 协议消息格式。

**主要特性：**
- **RFC8785 合规性**：用于确定性签名生成的规范 JSON 序列化
- **类型安全**：基于 Pydantic 的验证，具有全面的类型提示
- **抽象基类**：定义许可、签名、验证结果和确认的契约
- **协议消息**：标准化的 HTTP 402 请求/响应负载模式
- **版本管理**：协议版本协商和兼容性处理
- **区块链无关**：所有区块链特定实现继承的基础模型

**主要组件：**
- `CanonicalModel`：符合 RFC8785 的具有确定性 JSON 序列化的基础模型
- 抽象类型：`BasePermit`、`BaseSignature`、`BaseVerificationResult`、`BaseTransactionConfirmation`
- HTTP 协议：`ClientRequestHeader`、`Server402ResponsePayload`、`ClientTokenRequest`、`ServerTokenResponse`
- 支付模型：定义支付需求的 `BasePaymentComponent`
- 状态枚举：`VerificationStatus`、`TransactionStatus`
- 版本处理：`ProtocolVersion`、`SupportedVersions`

**目的：**
作为类型基础，确保服务器、客户端、适配器和引擎组件之间一致的数据结构和验证。

::: x402_mock.schemas

## Engine

**事件驱动执行引擎**

Engine 模块实现了一个复杂的事件驱动架构，用于编排支付协议工作流。它提供了一个类型化的事件系统，带有事件总线，允许订阅者挂钩到支付生命周期、监控执行流程、捕获错误并在关键执行点自定义行为。

**主要特性：**
- **类型化事件系统**：强类型事件，代表支付处理的每个阶段
- **事件总线**：用于解耦事件处理的发布-订阅模式
- **钩子订阅**：使用 `add_hook()` 订阅特定事件类型的处理程序
- **事件链执行**：具有状态转换的顺序事件处理
- **全面的事件**：请求初始化、令牌交换、验证、结算、错误
- **依赖注入**：业务逻辑与基础设施依赖的清晰分离
- **异常层次结构**：用于细粒度错误处理的丰富异常类型
- **异步原生**：为异步执行构建，支持 asyncio

**关键事件类型：**
- `RequestInitEvent`：带有可选授权令牌的初始请求
- `RequestTokenEvent`：用于令牌交换的支付许可提交
- `Http402PaymentEvent`：带有支付方案的支付要求响应
- `VerifySuccessEvent` / `VerifyFailedEvent`：签名验证结果
- `SettleSuccessEvent` / `SettleFailedEvent`：链上结算结果
- `TokenIssuedEvent`：成功的访问令牌生成
- `AuthorizationSuccessEvent`：成功的请求授权

**主要组件：**
- `EventBus`：具有订阅者管理的中央事件分发器
- `EventChain`：编排事件序列执行
- `Dependencies`：共享基础设施的不可变容器
- 类型化事件：所有事件都继承自 `BaseEvent`
- 自定义异常：针对不同失败场景的详细错误类型

**使用模式：**
开发人员可以使用 `event_bus.subscribe(EventType, handler)` 订阅自定义处理程序到事件，以拦截事件、记录交易、触发 webhook 或在支付流程的任何点实现自定义业务逻辑。

::: x402_mock.engine

## MCP

**模型上下文协议（MCP）工具集成**

MCP 模块将 x402-mock 的支付能力以 [Model Context Protocol](https://modelcontextprotocol.io/) 工具的形式暴露出来，使 LLM Agent（如 GitHub Copilot、Claude、GPT 等）能够直接调用，无需手动编写支付流程代码即可完成完整的 402 支付交互。

> **安装依赖**：MCP 支持作为可选依赖提供，使用以下命令安装：
> ```bash
> uv sync --extra mcp
> ```

**主要特性：**
- **零代码支付**：LLM Agent 通过自然语言指令即可触发完整的 402 支付流程
- **角色分离**：Client 角色（签名 + 请求）与 Server 角色（验证 + 结算）各自独立注册工具
- **stdio 传输**：基于标准 I/O 的进程通信，与所有主流 MCP 宿主（VS Code、Claude Desktop 等）兼容
- **自动支付重试**：`source_request` 工具封装了完整的 402 拦截 → 签名 → 重试流程
- **类型安全**：工具参数和返回值均基于 Pydantic 类型系统

**主要组件：**
- `FacilitorTools`：核心类，按角色向 `FastMCP` 实例注册工具

---

### `FacilitorTools`

**构造函数参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `adapter_hub` | `AdapterHub` | 是 | 已配置支付方式的适配器中枢 |
| `mcp` | `FastMCP` | 是 | FastMCP 服务器实例，工具将注册到此实例上 |
| `client_role` | `bool` | 否 | `True` 注册客户端工具，`False`（默认）注册服务端工具 |

**示例**

```python
from mcp.server.fastmcp import FastMCP
from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.mcp.facilitor_tools import FacilitorTools

hub = AdapterHub(evm_private_key="0x...")
mcp = FastMCP("x402")

# 服务端角色：注册 verify_and_settle 工具
FacilitorTools(adapter_hub=hub, mcp=mcp, client_role=False)

# 客户端角色：注册 signature + source_request 工具
# FacilitorTools(adapter_hub=hub, mcp=mcp, client_role=True)

mcp.run()
```

---

### MCP 工具一览

#### `source_request`（客户端）

访问受 402 保护的资源，自动完成签名与支付重试，是 LLM Agent 最常用的入口工具。

**参数**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `url` | `str` | 必填 | 目标资源 URL |
| `method` | `str` | `"GET"` | HTTP 方法 |
| `headers` | `dict \| None` | `None` | 额外请求头 |
| `timeout` | `float` | `30.0` | 请求超时时间（秒） |

**返回值**

```python
{
    "status_code": 200,          # HTTP 状态码
    "headers": { ... },          # 响应头字典
    "body": "..."                # 响应体字符串
}
```

**内部流程**

```
发送请求
  └─> 收到 402？
        ├─ 是 → 解析支付组件 → 签名 permit → 携带令牌重试 → 返回最终响应
        └─ 否 → 直接返回响应
```

---

#### `signature`（客户端）

根据服务端 402 响应中的支付组件列表，从本地注册的支付方式中匹配并生成签名的 permit，供后续提交至 `/token` 端点。

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `list_components` | `List[PaymentComponentTypes]` | 服务端返回的支付组件列表 |

**返回值**：已签名的 `PermitTypes` 对象（`EVMTokenPermit` 或其他链的对应类型）

---

#### `verify_and_settle`（服务端）

验证支付 permit 签名并在链上完成结算，一步完成，无需单独的令牌发放流程。

**参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| `permit` | `PermitTypes` | 已签名的支付 permit |

**返回值**（三选一）

| 返回类型 | 含义 |
|----------|------|
| `SettleSuccessEvent` | permit 有效，链上结算已确认 |
| `SettleFailedEvent` | permit 有效，但链上结算失败 |
| `VerifyFailedEvent` | permit 签名无效 |

**事件流**

```
RequestTokenEvent
  └─> 验证签名
        ├─ 成功 → VerifySuccessEvent → 链上结算
        │           ├─ 成功 → SettleSuccessEvent
        │           └─ 失败 → SettleFailedEvent
        └─ 失败 → VerifyFailedEvent
```

---

### MCP 配置示例（VS Code / GitHub Copilot）

将以下内容保存为项目根目录下的 `.vscode/mcp.json`，即可在 VS Code 的 Copilot Agent 模式中直接使用 x402-mock 支付工具：

```json
{
  "servers": {
    "X402-Mock-Server": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "example/mcp_server_example.py"],
      "env": {
        "X402_TOKEN_KEY": "dev-secret-change-me",
        "EVM_PRIVATE_KEY": "your_private_key_here",
        "EVM_INFURA_KEY": "your_infura_key_here"
      }
    },
    "X402-Mock-Client": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "example/mcp_client_example.py"],
      "env": {
        "EVM_PRIVATE_KEY": "your_private_key_here",
        "EVM_INFURA_KEY": "your_infura_key_here"
      }
    }
  }
}
```

::: x402_mock.mcp