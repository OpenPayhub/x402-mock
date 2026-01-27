
# x402_mock

`x402_mock` 是一个用于 **演示与验证 x402 支付流程** 的实验性模块。

该模块基于 **Web3 + USDC（ERC20）**，完整跑通了以下链路：

> **Client → Server → On-chain（Permit + Transfer）**

目前完成了：
- client 向 server 发起支付请求  
- server 对请求进行校验并构造链上交易  
- 基于 `permit` 的签名验证  
- 最终完成链上 USDC 转账  

本模块的目标不是生产可用，而是 **让 x402 的支付语义与交互流程足够清晰、可验证、可演示**，为未来 **Agent-to-Agent 的自动化支付** 打基础。

---

## 设计目标

- 🧪 **流程优先**：关注 x402 的交互与语义，而非工程完备性  
- 🧠 **可理解性**：尽量减少隐藏逻辑，方便阅读与学习  
- 🤖 **面向 Agent**：为未来 Agent 自动发起 / 接受 / 执行支付做准备  
- 🔌 **可扩展性**：后续可自然演进为多链、多资产、多支付通道  

---

## 交互流程

整体交互流程如下所示：

```

Client
│
│  (x402 request)
▼
Server
│
│  (permit verification)
│
▼
On-chain (USDC)

```

> 📌 流程图请参考下图（示意图由使用者自行绘制）  
> [图片](../../../assets/work_flow.png)

---

## 运行说明（Demo）

### 1. 安装依赖

本模块使用 `extra` 方式引入依赖：

```bash
uv sync --extra x402
```

---

### 2. 网络与资产准备

在启动 Demo 前，**强烈建议使用测试网络**：

* 网络：`Sepolia`
* 资产要求：

  * 测试用 USDC（ERC20）
  * 少量 Sepolia ETH（用于 Gas）

如果余额不足，可通过官方 Faucet 免费领取。

---

### 3. Server 环境配置

配置路径：

```
x402_mock/servers/env.server
```

需要提供以下环境变量：

* `INFURA_KEY`
* `WALLET_ADDRESS`
* `PRIVATE_KEY`

启动 Server：

```bash
uv run -m src.terrazip.x402_mock.servers.server
```

Server 启动后，将监听来自 client 的支付请求。

---

### 4. Client 环境配置

配置路径：

```
x402_mock/clients/env.client
```

同样需要配置付款方的：

* `INFURA_KEY`
* `WALLET_ADDRESS`
* `PRIVATE_KEY`

启动 Client 后：

* Client 将自动发起请求
* 完成与 Server 的交互
* 并最终触发链上扣款

无需额外人工操作。

---

## 当前状态

* ✅ Client → Server 请求流程
* ✅ Permit 签名与验证
* ✅ 链上 USDC 转账，tx_hash 返回可查
* 🧪 Demo 级可运行实现

---

## Roadmap

> 以下为规划方向，非承诺时间表

* [ ] 抽象统一的支付接口
* [ ] 支持更多链（EVM / Non-EVM）
* [ ] 支持更多资产（Native / ERC20 / Stablecoin）
* [ ] 引入可生产模式（风控、重试、状态机）
* [ ] 面向 Agent 的支付 SDK / 协议封装

---

## 声明

本模块为 **实验性 / 教学用途**，不建议直接用于生产环境。
如用于真实资产，请自行完成安全审计与风险控制。

---

如果你在研究：

* x402 协议
* Agent 经济系统
* 自动化链上支付

欢迎交流与共建。

