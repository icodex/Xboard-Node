# GFW 协议组合推荐与 CircumVolve 论文分析

我的判断：**主力优先选 VLESS + REALITY + Vision，或 VLESS + XHTTP + TLS + CDN；再保留一种 UDP 方案和一个非 443 入口。** 持续可用更依赖几条失败原因不同的连接路径，而不是把所有节点都换成同一种“最强协议”。

昨天的测试说明协议组合、配置下发和客户端互通已经跑通。抗封锁还要看运营商、地区、节点 IP、SNI 和持续传输行为。**下面十组是我的部署优先级判断 `[INFERENCE]`，不是论文给出的排名，也没有可据以填写的全国穿透率。**

先仔细分析你给的论文，再给完整配置表。

## 这篇论文真正改变了哪些判断

[CircumVolve](https://gfw.report/publications/ccs26/zh/) 的重要性在于：它证明了可以用自动化搜索，持续发现**审查设备与真实服务器在协议解析上的差异**。它找到 47 类策略，其中针对中国的有 34 类；这些是规避策略，并不是 34 种代理协议。

与我们选择节点搭配直接相关的结果如下。

| 论文发现 | 中国测量结果 | 对节点选型的实际意义 |
|---|---|---|
| 将 ClientHello 拆成多条 **TLS 记录**，包括在 SNI 内或握手头部拆分 | 在论文测量点有效 | TLS 记录拆分值得作为客户端侧的条件性增强；必须确认客户端真正改写了记录边界 |
| 增大 ClientHello，通过填充、密码套件或扩展迫使 **TCP 分段** | 论文表 5 中未绕过中国检测 | 不能把“拆成多个 TCP 包”和“拆成多条 TLS 记录”视为同一种能力 |
| 将 QUIC ClientHello 拆进多个 `CRYPTO` 帧 | 在中国测量点有效 | QUIC 的握手组织方式影响检测结果；普通应用数据分片不等于这个策略 |
| QUIC 保留位、前置 ACK、诱饵 `CRYPTO` 帧等结构操作 | 若干策略有效 | 有研究价值，但通常需要改动 QUIC 实现，不能当作面板里已有的通用开关 |
| 明文 HTTP/2，即 h2c | 绕过了被测 HTTP Host 检查 | 证明部分 DPI 对 HTTP/2 解析不足；**不代表裸 h2c 适合直接承载公网代理** |
| DNS 压缩指针、多问题等变形 | 部分策略有效，解析器兼容性差异明显 | 适合专门研究；生产节点仍应先解决可靠的域名引导解析和隧道内 DNS |

这里有三个必须保留的证据边界：

1. **TLS 和 QUIC 的主要评估停留在初始握手阶段。** 收到 `ServerHello`、Initial 或 Retry，不等于完成证书验证、代理认证和长期大流量传输。论文 §5 也明确承认这一限制。
2. **中国测量点是阿里云、腾讯云 VPS。** 不能直接外推为所有家庭宽带、移动网络和校园网都有效。另有[教育网等网络的社区报告](https://github.com/net4people/bbs/issues/550)指出 TLS 记录拆分失效，但其覆盖范围尚不能与受控测量等同。
3. **论文没有比较 REALITY、XHTTP、Naive、AnyTLS、Hysteria2 的长期抗封锁率，也没有评估完全加密协议。** 因此它能指导增强方向，不能直接产生代理协议排行榜。

结合其他公开研究，我会据此做四个判断：

- **“全随机”不等于没有特征。** GFW 对完全加密流量的被动识别已有公开测量；因此裸 Shadowsocks 或单纯随机化，不是我的主力首选。[研究依据](https://gfw.report/publications/usenixsecurity23/en/)
- **QUIC 不会自动隐藏 SNI。** Initial 密钥可由公开信息推导，GFW 自 2024 年起已有解密 Initial、检查 SNI 的测量证据。[研究依据](https://gfw.report/publications/usenixsecurity25/en/)
- **地区和网络路径会改变结果。** 区域审查设备与国家级设备可能叠加，同一份配置在不同地区表现不同，有研究支持。[研究依据](https://gfw.report/publications/sp25/en/)
- **443 应作为主入口，但不应是唯一入口。** 有公开测量的 8 月 20 日 TCP 443 无条件封锁发生在 **2025 年**，持续约 74 分钟；它说明端口层封锁可能越过上层协议，但不能被当作今年的常态。[事件报告](https://gfw.report/blog/gfw_unconditional_rst_20250820/en/)

对于你提到的今年几轮封锁，现有公开资料不足以逐轮建立统一、可复核的全国时间线；下面不会把社区现象或商业宣传写成已确认的全国规则。

## 我推荐的十组搭配

表中端口均为**客户端连接的公网入口端口**。多项使用同一个端口，是分别部署时的建议，不表示它们可以直接抢占同一个 IP 的同一监听端口。

加密字段统一说明：

- **TLS 1.3 AEAD**：通常协商 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384` 或 `TLS_CHACHA20_POLY1305_SHA256`。保留正常客户端的协商行为；强行只留某一种密码套件，没有已知的抗封锁收益。
- **VLESS `encryption=none`**：关闭的是 VLESS 自身附加加密，表中仍有 TLS 或 REALITY 提供外层保护。
- **REALITY**：包含自身认证和 TLS 外观机制；X25519 密钥不是让用户选择的对称加密算法。
- **混淆、填充与加密是不同能力**，表中分别列出。

| 优先级 | 协议搭配与定位 | 推荐公网端口 | 加密算法／安全层 | 混淆、伪装或填充 | 关键参数与部署条件 | 主要局限 |
|---|---|---|---|---|---|---|
| **1** | **VLESS + TCP/RAW + REALITY + Vision**；直连主力 | **TCP 443**；备用 **TCP 8443** | REALITY / TLS 1.3 AEAD；VLESS `encryption=none` | REALITY 外观与未授权连接回落；Vision 对内层握手进行填充 | 推荐 xray；`flow=xtls-rprx-vision`；`fingerprint=chrome`；独立随机密钥和 `shortId`；`serverName` 必须是目标接受的名称；选择适合该节点网络位置的 `target:443` | 直接暴露入口 IP；IP 或路由被封后，REALITY 无法恢复可达性；目标站点和客户端版本影响效果 |
| **2** | **VLESS + XHTTP + TLS + CDN，使用 HTTP/2**；另一类主力入口 | **TCP 443**；CDN 支持时备用 **TCP 8443** | 客户端至 CDN、CDN 至源站分别使用 TLS；VLESS `none` | 真实 HTTPS 承载；XHTTP header padding、XMUX | xray；`alpn=h2`；`mode=auto`，对不兼容的中间盒选 `packet-up`；独立 `path`；保留默认 padding/XMUX；代理路径禁缓存；源站限制为可信回源入口 | CDN 域名和边缘 IP 仍可能被封；受 CDN 超时、WAF、回源策略影响；CDN 会终止外层 TLS |
| **3** | **VLESS + XHTTP + REALITY，使用 HTTP/2**；直连的另一种传输形态 | **TCP 443**；备用 **TCP 8443** | REALITY / TLS 1.3 AEAD；VLESS `none` | REALITY + XHTTP header padding、XMUX | xray；XHTTP `mode=auto`；独立 `path`；`fingerprint=chrome`；**此处不配置 Vision flow**；通常不能放到终止 TLS 的普通 HTTP CDN 后面 | 与第 1 项共享直连 IP 风险；没有充分证据证明叠加 XHTTP 后必然比 Vision 更抗封 |
| **4** | **NaiveProxy + HTTPS HTTP/2 + 真实 HTTPS 前端**；侧重客户端协议栈一致性 | **TCP 443**；备用 **TCP 8443** | TLS 1.3 AEAD；HTTPS CONNECT 认证 | Chromium 网络栈；Naive 原生 padding；支持鉴权路由的前端提供探测抵抗 | 使用更新的 Chromium/Naive 客户端；`alpn=h2`；启用 Naive padding；前端必须支持 CONNECT 和正确的鉴权转发 | 不能随意套普通 CDN；只启动一个兼容入站，不代表已经拥有完整的网站外观和探测抵抗 |
| **5** | **AnyTLS + TLS + 原生 padding**；TCP 备用主力 | **TCP 443**；备用 **TCP 8443** | TLS 1.3 AEAD | AnyTLS 分包、填充与会话复用，针对嵌套 TLS 的长度特征 | sing-box；有效域名证书；开启证书验证；`padding_scheme` 先用实现默认值；保留正常 TLS 指纹 | 填充不能隐藏 IP 和明文 SNI；长期抗封锁的公开对比证据仍有限 |
| **6** | **VLESS + WebSocket + TLS + CDN**；客户端覆盖广的备用入口 | **TCP 443**；CDN 支持时备用 **TCP 8443** | 两段 TLS；VLESS `none` | WebSocket 经真实 HTTPS 承载；通常没有独立强混淆层 | xray 或 sing-box；`Host`、SNI、证书和路由配置一致；独立 WS `path`；CDN 开启 WebSocket；源站不公开直连入口 | WS 常用实现仍有可观察特征；不要强行给传统 WS 配 `h2`；我把它排在 XHTTP 后面 |
| **7** | **Trojan + gRPC + TLS + CDN**；已有 Trojan 客户端生态的备用 | **TCP 443**；CDN 支持时备用 **TCP 8443** | TLS 1.3 AEAD；Trojan 自身主要提供认证 | gRPC / HTTP/2 承载；没有额外通用混淆算法 | xray 或 sing-box；`alpn=h2`；独立 `serviceName`；CDN 明确支持并启用 gRPC；核对长连接超时 | gRPC 支持依赖 CDN；TLS 内的代理流量仍可能具有统计特征，不能因为使用 Trojan 就认定不可识别 |
| **8** | **VLESS + XHTTP + TLS + CDN，客户端使用 HTTP/3**；UDP 路径备用 | **UDP 443**；备用端口由 CDN 实际支持决定 | QUIC 使用 TLS 1.3 AEAD；VLESS `none` | 真实 HTTP/3 承载 + XHTTP padding | xray 客户端；`alpn=h3`；`mode=packet-up`；CDN 边缘启用 HTTP/3；回源可以是 TCP HTTP/1.1 或 HTTP/2 | QUIC Initial 的 SNI 仍可被检查；UDP 被封或严重限速时不可用；必须保留第 2 项的 H2 入口 |
| **9** | **Hysteria2 + 原生 QUIC/TLS + HTTP/3 masquerade，不开 obfs**；弱网与 UDP 备用 | **UDP 443**；备用 **UDP 8443** | QUIC / TLS 1.3 AEAD | 标准 HTTP/3 行为；认证与请求 padding；未认证请求返回实际内容或反代网站 | 此项目推荐 sing-box；`obfs` 关闭；有效证书和正确 SNI；配置 `masquerade`；优先使用 BBR 自适应，固定带宽参数应依据实际线路 | QUIC、SNI 和 UDP 策略仍是风险；高吞吐不等于更抗封锁 |
| **10** | **Hysteria2 + Salamander**；针对 QUIC 特征封锁的异构备用 | **UDP 8443**；另留 **UDP 443** 入口供实测选择 | 内层仍为 QUIC/TLS 1.3 AEAD | **Salamander**：基于预共享密码和随机 salt 派生掩码，对 QUIC 报文进行 XOR 混淆 | **sing-box 内核**；客户端和服务端 `obfs.type=salamander`、密码完全一致；密码使用独立强随机值；先不启用跳端口 | 外观变为随机 UDP，**不再是标准 HTTP/3 网站**；无法对抗整体 UDP 封锁，也不保证优于第 9 项 |

以上按抗封锁部署价值排序；**第 8—10 项的价值主要是提供与 TCP 不同的失败路径，而不是普遍比前面的方案更强。**

配置依据：[REALITY 官方参数](https://xtls.github.io/config/transports/reality.html)、[VLESS/Vision 适用范围](https://xtls.github.io/config/outbounds/vless.html)、[XHTTP 维护者说明](https://github.com/XTLS/Xray-core/discussions/4113)、[NaiveProxy 设计与部署](https://github.com/klzgrad/naiveproxy)、[AnyTLS 参数](https://sing-box.sagernet.org/configuration/inbound/anytls/)、[Hysteria2 配置与混淆](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)。

## 落到我们这个项目，几个参数不能混用

我核对了当前配置生成代码和参数支持文档，下面这些区别会直接影响实际结果：

- **XHTTP 选 xray 内核。** 当前项目已转发 `path`、`host`、`mode` 和 `extra`；sing-box 路径不支持 XHTTP。
- **Hysteria2 + Salamander 选 sing-box。** 项目当前 xray 路径不会应用 Hysteria 的 obfs 和 masquerade 参数。面板填了参数，不等于运行中的内核采用了它。
- **Vision 用于第 1 项的 TCP/RAW 搭配。** 表中的 XHTTP、WebSocket、gRPC 方案不照搬 `xtls-rprx-vision`。
- **uTLS 指纹是客户端行为。** 服务端面板保存 `fingerprint=chrome`，只有订阅生成和客户端执行到位，才会改变网络上的 ClientHello。
- **TLS 记录拆分也主要需要客户端实现。** 不能只在境外服务端设置“分片”，就认为中国出口方向的 ClientHello 已按论文方式拆分。

项目对应依据：[参数支持表](docs-params-support.md)、[XHTTP 配置生成](internal/kernel/xray/config.go)、[AnyTLS 与 Naive 配置生成](internal/kernel/singbox/config.go)。

**我不会把 TLS 分片、ECH、跳端口统一作为十组配置的必选增强。** TLS 分片只针对部分解析路径；ECH 还依赖客户端、密钥分发和网络对外层 ClientHello 的处理；跳端口只可能帮助某些端口级封锁，不能解决整 IP 封锁。它们应该针对已经观察到的失败原因启用。

如果由我安排实际部署，会先上线这四类入口：

- **直连主力：第 1 项 REALITY + Vision。**
- **CDN 主力：第 2 项 XHTTP + TLS/H2。**
- **另一种 TCP 实现：第 4 项 Naive，或第 5 项 AnyTLS。**
- **UDP 备用：第 9 项与第 10 项各保留一条，分别观察原生 QUIC 和随机 UDP 在目标网络的表现。**

这些入口应尽量分散到不同 IP、网络提供商和域名上。**同一 IP 上开放十种协议，仍然共享一次 IP 封锁就全部失效的风险。** 对它们的最终排序，应以目标地区的连接成功、完整代理请求、持续传输和一段时间内的存活情况为准；昨天的互通测试是这个验证过程的起点。
