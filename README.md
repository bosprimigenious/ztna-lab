# ZTNA Lab

![Tests](https://github.com/bosprimigenious/ztna-lab/actions/workflows/test.yml/badge.svg)

这是一个面向**自有网关**的独立 ZTNA/VPN 架构实验。它只监听并访问
`127.0.0.1`，不是 aTrust 兼容客户端，不连接北邮或任何真实校园网。

当前版本按用户可见能力对齐，而不是复刻商业产品协议：

```text
LabClient
   | HTTPS / TLS 1.3：密码 + TOTP + 设备公钥
   v
ControlPlane：姿态策略、会话、虚拟 IP、Ed25519 授权与签名清单
   |
   +------------------ verify-only key ------------------+
                                                         v
LabClient ===== TLS 1.3 + 连接持有证明 =====> Gateway =====> 注册的本地资源
   |
   +--> 签名清单 --> DryRunNetworkHelper（只在内存中预览/应用/回滚）
```

已实现的实验能力包括：

- 密码 + 单次 TOTP、多因素登录和基础设备姿态判断
- Ed25519 短期授权，绑定会话、设备密钥、资源、虚拟 IP 和租约代际
- Ed25519 签名的资源/路由/DNS 清单及篡改检测
- `100.64.0.0/24` 虚拟 IP 租约和 `198.18.0.0/24` 内存 Fake DNS
- 最长前缀分流、版本化 TCP/L3 帧、序列号和非法状态转换拒绝
- TLS 1.3 数据网关、每次数据/控制请求的设备签名和请求 ID 防重放
- 心跳刷新短期授权与清单、绝对/空闲超时、登出撤销和 IP 回收
- 独立管理员密钥保护的有界内存审计
- 只计算差异、绝不修改 Windows 网络配置的网络助手接口

刻意不包含任意目标代理、系统路由/TUN/WFP/DNS 修改、管理员权限、
aTrust 私有协议/票据/证书，或任何自动登录和 MFA 绕过。

## 运行

在本目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m labztna.demo
```

程序生成一次性 CA、控制面/网关独立叶证书和随机签名密钥，启动三个只监听
`127.0.0.1` 的服务，完成登录、清单获取、心跳、帧化资源请求和登出。
演示密码只存在于进程内，不写入文件。

## 测试

```powershell
python -m pytest -q
```

## 文档

- [DESIGN.md](DESIGN.md)：信任边界、协议和加密设计
- [CAPABILITY_MATRIX.md](CAPABILITY_MATRIX.md)：逐项能力对照和缺口
- [DEPLOYMENT.md](DEPLOYMENT.md)：迁移到自有网关的生产化分阶段方案
- [VERIFICATION.md](VERIFICATION.md)：实际测试记录和未验证项

## 安全边界

这是教学 PoC，不是生产 VPN。真实部署前仍需正式 PKI、OIDC/企业 IdP、
可信设备证明、KMS/HSM、持久会话和吊销、集中审计、限流、HA，以及经过
审计的 WireGuard/IPsec 数据面。项目不设计自有加密算法。
