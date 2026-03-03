# x402-mock

<p align="center">
  <a href="README.md">
    <img src="https://img.shields.io/badge/EnglishVersion-blue?style=flat-square&logo=github" alt="English Version" />
  </a>
</p>

> 目录： [目录](./docs/index.zh.md)

> 快速开始: [快速开始](./docs/quick_start.zh.md)

> 文档： [文档](./docs/reference.zh.md)

> 代码示例： [示例example](./example/)

> 📚 协议入门：[x402-mock用了哪些evm协议](./docs/evm_docs.zh.md)（[预留英文版](./docs/evm_docs.md)）

---

> 🌟 如果本项目或文档对您有所帮助，欢迎给我们点一个 **Star** —— 这是对我们最大的鼓励，感谢您的支持！[![GitHub stars](https://img.shields.io/github/stars/OpenPayhub/x402-mock?style=social)](https://github.com/OpenPayhub/x402-mock) 

## 项目综述：x402-mock
x402-mock 是一个专为 AI Agent 及服务端开发者设计的开源收款集成方案。我们的核心目标是提供一套即插即用的 SDK，帮助开发者在自己的服务端快速实现链上收款与转账功能，无需从零开始处理复杂的支付逻辑。

除了作为一个实用的工具插件，项目还承担了 HTTP 402 (Payment Required) 协议以及区块链协议的科普工作。我们正在整理和完善详尽的说明文档，旨在帮助想了解 AI 支付和链上协议的用户快速上手。无论是为了解决项目中的支付需求，还是想深入研究相关协议标准，x402-mock 都能提供从代码实现到理论参考的全方位支持，共同推动 AI 支付生态的开发效率。

---

## 流程图

> 📌 完整交互流程示意图请参考下图

> ![图片](.//assets/402workflow.png)

---

[**网页地址**](https://openpayhub.github.io/x402-mock/)

### 网络选择建议

**生产环境使用前，强烈建议先在测试网进行充分测试：**

- **测试网推荐**：Sepolia（以太坊）、Mumbai（Polygon）等
- **测试资产**：可通过各链官方 Faucet 免费领取测试 ETH 和测试 USDC
- **验证流程**：确认完整支付流程、链上结算、异常处理等功能正常

测试通过后，可切换到主网进行生产部署。

---

## 当前状态

* ✅ 完整的 HTTP 402 支付流程
* ✅ Client → Server 请求与响应
* ✅ 支付方式协商与匹配
* ✅ USDC：ERC-3009 离线签名与验证（更省 gas）
* ✅ 通用 ERC20：Permit2 离线签名与验证（覆盖大多数 ERC20）
* ✅ 链上 USDC 转账，tx_hash 可查
* ✅ 异步链上结算，不阻塞业务
* ✅ 覆盖 EVM 链，理论上支持所有代币的签名（Ethereum、Polygon、Arbitrum、Optimism 等）
* 🚀 生产级可运行实现

---

## Roadmap

* [ ] 支持 智能合约钱包地址收款
* [ ] 支持 EIP-6492（未部署合约的签名验证）
* [ ] 支持 SVM（Solana Virtual Machine）及 Solana 生态
* [ ] 配合 大模型调用

---

## 声明与建议

本模块生产可用，但在部署到生产环境前，请注意：

⚠️ **强烈建议先在测试网（如 Sepolia）进行充分测试**  
✅ 确认完整支付流程、异常处理、链上结算等功能符合预期  
🔒 如用于真实资产，请务必完成安全审计与风险控制  
💰 建议设置合理的单笔交易限额和风控机制

---

如果你在研究：

* x402 协议
* Agent 经济系统
* 自动化链上支付

欢迎交流与共建。

