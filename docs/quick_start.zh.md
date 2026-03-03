# 快速开始

x402-mock 是一个基于 HTTP 402 状态码的支付协议实现，支持 EVM 区块链上的代币支付。本指南将帮助您快速上手。

## 安装

本项目使用 `uv` 作为包管理工具。

```bash
uv add x402-mock
uv sync
```

### 环境配置

在项目根目录创建 `.env` 文件，配置您的私钥和 RPC 服务密钥：

```env
# 必需：EVM 私钥（用于签名和收款）
EVM_PRIVATE_KEY=your_private_key_here

# 可选：Infura 或 Alchemy 的 API 密钥（用于访问区块链网络）
EVM_INFURA_KEY=your_infura_key_here
EVM_ALCHEMY_KEY=your_alchemy_key_here
```

## 核心概念

### 支付流程概述

x402-mock 实现了职责分离的支付流程，类似于电影院的售票和验票系统：

1. **Server（收款方）**：提供服务并接受支付，类似于电影院
2. **Client（付款方）**：请求服务并完成支付，类似于观众
3. **支付流程**：
   - Client 请求受保护的资源
   - Server 验证 Client 的访问令牌（类似验票）
   - 如果令牌无效，返回 402 状态码 + 支付信息（类似指引去售票处）
   - Client 根据支付信息完成签名支付（类似买票）
   - Client 获取访问令牌后重新请求资源（类似持票入场）

### 状态码 402 的职责分离

HTTP 402 "Payment Required" 状态码在本项目中实现了职责分离：
- **Server 端**：只负责验证访问令牌的有效性，不处理支付逻辑
- **支付验证**：由独立的 `/token` 端点处理，接收支付签名并发放访问令牌
- **Client 端**：自动处理 402 响应，完成支付流程后重试请求

这种设计使得支付逻辑与业务逻辑解耦，提高了系统的可维护性和安全性。

## Server（收款方）

Server 是提供服务并接受支付的一方。主要职责包括：
1. 定义接受的支付方式（链、网络、代币）
2. 验证支付签名的真实性和有效性
3. 完成链上转账结算
4. 发放访问令牌

### 创建 Server 实例

```python
from x402_mock.servers import Http402Server, create_private_key
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

# 生成访问令牌签名密钥
token_key = create_private_key()

# 创建 Server 实例（继承自 FastAPI）
app = Http402Server(
    token_key=token_key,      # 访问令牌签名密钥
    token_expires_in=300      # 令牌有效期（秒）
)
```

#### Http402Server 参数说明

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `token_key` | str | 是 | 访问令牌签名密钥，可使用 `create_private_key()` 生成 |
| `token_expires_in` | int | 否 | 访问令牌有效期（秒），默认 3600 |
| `enable_auto_settlement` | bool | 否 | 是否自动结算支付，默认 True |
| `token_endpoint` | str | 否 | 令牌交换端点路径，默认 "/token" |

### 添加支付方式

```python
# 添加 EVM 支付方式
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,          # 支付金额（人类可读单位）
        currency="USDC",     # 代币符号
        caip2="eip155:11155111",  # CAIP-2 链标识符
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"  # 代币合约地址
    )
)
```

#### EVMPaymentComponent 参数说明

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `amount` | float | 是 | 支付金额（人类可读单位，如 0.5 USDC） |
| `currency` | str | 是 | 代币符号（如 "USDC", "USDT", "ETH"） |
| `caip2` | str | 是 | CAIP-2 链标识符（格式：`eip155:<chain_id>`） |
| `token` | str | 建议 | 代币合约地址（0x 开头，42 字符） |
| `pay_to` | str | 否 | 收款地址，默认使用环境变量私钥对应的地址 |
| `rpc_url` | str | 否 | RPC 节点 URL，默认使用公共节点或根据环境变量自动配置 |
| `token_name` | str | 否 | 代币名称，自动获取时可省略 |
| `token_decimals` | int/str | 否 | 代币精度，自动获取时可省略 |
| `token_version` | int/str | 否 | 代币版本，自动获取时可省略 |

**注意**：`token`、`token_name`、`token_decimals`、`token_version` 如未提供，系统会根据 `caip2` 和 `currency` 自动查询。

### 保护 API 端点

使用 `@app.payment_required` 装饰器保护需要支付的端点：

```python
@app.get("/api/protected-data")
@app.payment_required
async def get_protected_data(payload):
    """需要支付才能访问的端点"""
    return {
        "message": "Payment verified successfully",
        "user_address": payload["address"]
    }
```

### 事件处理

Server 提供了事件系统，您可以监听支付流程中的各种事件：

```python
from x402_mock.engine.events import SettleSuccessEvent

@app.hook(SettleSuccessEvent)
async def on_settle_success(event, deps):
    """支付成功时的处理逻辑"""
    print(f"✅ 支付成功: {event.settlement_result}")
    # 可以在这里记录日志、发送通知等
```

可用的事件类型：
- `RequestInitEvent`: 请求初始化
- `RequestTokenEvent`: 令牌请求
- `TokenIssuedEvent`: 令牌发放
- `VerifyFailedEvent`: 验证失败
- `AuthorizationSuccessEvent`: 授权成功
- `Http402PaymentEvent`: 需要支付
- `SettleSuccessEvent`: 结算成功

## Client（付款方）

Client 是请求服务并完成支付的一方。主要职责包括：
1. 注册支持的支付方式
2. 自动处理 402 响应
3. 生成支付签名
4. 交换签名获取访问令牌

### 创建 Client 实例

```python
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

async with Http402Client() as client:
    # 注册支付方式
    client.add_payment_method(
        EVMPaymentComponent(
            caip2="eip155:11155111",
            amount=0.8,          # 最大支付金额限制
            currency="USDC",
            token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
        )
    )
    
    # 发送请求（自动处理 402 支付流程）
    response = await client.get("http://localhost:8000/api/protected-data")
    print(response.json())
```

#### Client 端 EVMPaymentComponent 的特殊说明

在 Client 端，`amount` 参数表示**最大支付金额限制**。如果 Server 要求的金额超过此限制，Client 将拒绝签名支付。

### 支付流程自动化

`Http402Client` 继承自 `httpx.AsyncClient`，完全兼容其所有方法。当收到 402 响应时，Client 会自动：

1. 解析支付要求
2. 匹配已注册的支付方式
3. 生成支付签名
4. 向 `/token` 端点交换访问令牌
5. 使用新令牌重试原始请求

整个过程对开发者透明，只需正常使用 HTTP 客户端即可。

## 完整示例

### Server 端完整示例

```python
from x402_mock.servers import Http402Server, create_private_key
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.engine.events import SettleSuccessEvent

# 创建 Server
token_key = create_private_key()
app = Http402Server(token_key=token_key, token_expires_in=300)

# 添加支付方式
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    )
)

# 支付成功事件处理
@app.hook(SettleSuccessEvent)
async def log_payment_success(event, deps):
    print(f"💰 收到支付: {event.settlement_result.authorized_amount} USDC")

# 受保护的 API 端点
@app.get("/api/premium-content")
@app.payment_required
async def get_premium_content(payload):
    return {
        "content": "这是付费内容",
        "paid_by": payload["address"],
        "timestamp": payload.get("timestamp")
    }

# 运行 Server（使用 uvicorn）
# uvicorn server:app --host 0.0.0.0 --port 8000
```

### Client 端完整示例

```python
import asyncio
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

async def main():
    async with Http402Client() as client:
        # 注册支付方式（支持多个）
        client.add_payment_method(
            EVMPaymentComponent(
                caip2="eip155:11155111",
                amount=1.0,      # 最多支付 1.0 USDC
                currency="USDC",
                token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
            )
        )
        
        # 请求受保护的内容（自动处理支付）
        response = await client.get("http://localhost:8000/api/premium-content")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ 获取到内容: {data['content']}")
            print(f"   支付方: {data['paid_by']}")
        else:
            print(f"❌ 请求失败: {response.status_code}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 高级配置

### 自定义 RPC 节点

```python
# Server 端指定 RPC 节点
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,
        currency="USDC",
        caip2="eip155:1",  # Ethereum 主网
        token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
    )
)
```

### 多链支持

```python
# 支持多个链的支付方式
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.1,
        currency="ETH",
        caip2="eip155:1",  # Ethereum 主网
        token=None  # 使用原生代币
    )
)

app.add_payment_method(
    EVMPaymentComponent(
        amount=1.0,
        currency="USDC",
        caip2="eip155:42161",  # Arbitrum
        token="0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
    )
)
```

## 链上信息获取工具

在配置支付方式时，您可能需要获取链上的各种信息，如 RPC 节点地址、代币合约地址、代币精度和版本等。x402-mock 提供了一系列工具方法来简化这些信息的获取。

### 导入工具方法

```python
from x402_mock.adapters.evm.constants import (
    EvmChainInfoFromEthereumLists,
    EvmPublicRpcFromChainList,
    EvmTokenListFromUniswap,
    fetch_erc20_name_version_decimals,
    get_rpc_key_from_env
)
```

### 方法说明

#### 1. `EvmChainInfoFromEthereumLists`
**功能**：从 ethereum-lists 仓库获取 EVM 链的详细配置信息。

**主要用途**：
- 获取链的 Infura/Alchemy RPC URL（包含 API 密钥占位符）
- 获取公共 RPC 节点列表
- 获取链的基本信息（名称、浏览器地址等）

**示例用法**：
```python
chain_info = EvmChainInfoFromEthereumLists()

# 获取 Infura RPC URL（需要填充 API 密钥）
infura_url = chain_info.get_infura_rpc_url("eip155:1")
# 返回类似：https://mainnet.infura.io/v3/{RPC_KEYS}

# 获取 Alchemy RPC URL（需要填充 API 密钥）
alchemy_url = chain_info.get_alchemy_rpc_url("eip155:1")
# 返回类似：https://eth-mainnet.g.alchemy.com/v2/{RPC_KEYS}

# 获取公共 RPC 节点列表
public_rpcs = chain_info.get_public_rpc_urls("eip155:1")
# 返回：["https://api.mycryptoapi.com/eth", ...]
```

#### 2. `EvmPublicRpcFromChainList`
**功能**：从 Chainlist.org 获取公共 RPC 节点信息。

**主要用途**：
- 获取无跟踪或有限跟踪的公共 RPC 节点
- 根据隐私偏好选择 RPC 节点
- 支持 HTTPS 和 WebSocket 协议

**示例用法**：
```python
rpc_finder = EvmPublicRpcFromChainList()

# 获取无跟踪的公共 RPC 节点
public_rpc = rpc_finder.pick_public_rpc(
    caip2="eip155:1",
    start_with="https://",
    tracking_type="none"
)
# 返回类似：https://rpc.ankr.com/eth

# 获取特定链的所有公共 RPC 信息
chain_rpcs = rpc_finder.get_specific_chain_public_rpcs("eip155:1")
```

#### 3. `EvmTokenListFromUniswap`
**功能**：从 Uniswap 官方代币列表获取代币信息。

**主要用途**：
- 获取代币的合约地址和精度
- 支持多链代币查询
- 自动缓存数据，减少网络请求

**示例用法**：
```python
token_finder = EvmTokenListFromUniswap()

# 获取代币地址和精度
address, decimals = token_finder.get_token_address_and_decimals(
    caip2="eip155:1",
    symbol="USDC"
)
# 返回：("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6)
```

#### 4. `fetch_erc20_name_version_decimals`
**功能**：直接从链上 RPC 查询代币的详细信息。

**主要用途**：
- 查询代币的 `name()`、`version()` 和 `decimals()` 函数
- 验证代币合约的完整信息
- 获取最新的链上数据

**示例用法**：
```python
# 从链上查询代币信息
name, version, decimals = fetch_erc20_name_version_decimals(
    rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
)
# 返回：("USD Coin", "2", 6)
```

#### 5. `get_rpc_key_from_env`
**功能**：从环境变量获取 RPC 服务商的 API 密钥。

**主要用途**：
- 安全地获取 Infura 或 Alchemy API 密钥
- 支持自定义环境变量名称
- 返回 `None` 时表示使用公共节点

**示例用法**：
```python
# 获取 Infura 密钥（默认）
infura_key = get_rpc_key_from_env("EVM_INFURA_KEY")

# 获取 Alchemy 密钥
alchemy_key = get_rpc_key_from_env("EVM_ALCHEMY_KEY")

# 使用密钥构建 RPC URL
if infura_key:
    rpc_url = f"https://mainnet.infura.io/v3/{infura_key}"
else:
    # 使用公共节点
    rpc_finder = EvmPublicRpcFromChainList()
    rpc_url = rpc_finder.pick_public_rpc("eip155:1")
```

### 自动填充支付组件

这些工具方法通常被 `EVMPaymentComponent` 内部使用，当您未提供完整信息时自动填充：

```python
# 只需提供基本信息，系统会自动查询缺失数据
payment = EVMPaymentComponent(
    amount=0.5,
    currency="USDC",
    caip2="eip155:1"
    # token、token_name、token_decimals、token_version 会自动查询
)

# 系统内部会：
# 1. 使用 EvmTokenListFromUniswap 获取 USDC 合约地址和精度
# 2. 使用 fetch_erc20_name_version_decimals 获取代币名称和版本
# 3. 使用 EvmPublicRpcFromChainList 获取公共 RPC 节点
# 4. 使用 get_rpc_key_from_env 检查是否有私有 RPC 密钥
```

### 最佳实践

1. **生产环境**：建议提供完整的 `token`、`rpc_url` 等信息，减少网络查询
2. **开发环境**：可以依赖自动查询，简化配置
3. **性能考虑**：首次查询会进行网络请求，后续使用缓存
4. **错误处理**：网络不可用时，自动回退到内置的默认配置

## 故障排除

### 常见问题

1. **402 响应后支付失败**
   - 检查私钥配置是否正确
   - 确认代币余额充足
   - 验证链 ID 和代币地址匹配

2. **令牌验证失败**
   - 检查 `token_key` 是否一致
   - 确认令牌未过期
   - 验证签名算法

3. **RPC 连接问题**
   - 检查网络连接
   - 确认 RPC URL 有效
   - 考虑使用备用节点

### 调试模式

启用详细日志记录：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 下一步

- 查看 [API 参考文档](./reference.zh.md) 获取详细接口说明
- 探索 [示例代码](../example/)
- 了解 [事件系统](./reference.zh.md#Engine) 实现自定义业务逻辑

---

**提示**：在生产环境中，请确保：
1. 使用安全的密钥管理方案
2. 配置适当的超时和重试策略
3. 监控支付成功率和失败原因
4. 定期更新依赖包以获取安全修复