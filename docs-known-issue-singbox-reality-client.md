# KNOWN ISSUE: sing-box fork client ↔ xray-kernel REALITY nodes (2026-10-31)

## Scope

`sing-box`（icodex fork）作为**客户端**无法连接 xray 内核的 REALITY 节点
（矩阵中的 vmess-reality / xhttp-reality 类型）。mihomo 与 xray 客户端不受影响。

服务端侧已修复：节点仓通过 `icodex/reality@xboard-compat`（a32241e97a03）恢复了
纯 X25519 key_share 回退（详见 commit 5282e46 的说明）。**服务端鉴权实测已通过**。

## 未修原因（实测证据链）

打点验证（服务端 `show:true` + 客户端 authKey 探针）：

1. 服务端对 sing-box 客户端的 REALITY 鉴权**成功**：
   `hs.c.ClientVer: [1 8 1]`、`ClientShortId: [1 35 171 205 0 0 0 0]`（=0123abcd）、
   `hs.c.conn == conn: true`——session_id 解密、shortId 匹配全部正确。
2. 客户端仍失败：`VerifyPeerCertificate` 回调**从未被调用**（打点无输出），
   客户端卡死在读取 ServerHello 之后的记录流，直到超时
   （`curl: (28) Connection timed out`），部分尝试表现为
   `reality verification failed` / `EOF`。
3. 根因：icodex/sing-box 内嵌的 utls/reality 客户端实现（2026-09 时代）
   与 `xtls/reality` HEAD 服务端的握手记录流不兼容——不是鉴权算法问题，
   是两侧 vendored TLS 栈的整体代差。上游 xtls 在 8cdf7bf 用 MLKEM 硬闸
   拒绝旧式 ClientHello，实质上就是承认了新旧栈不互通。

修复属于移植工程（把 sing-box 的 reality 客户端同步到 xtls/reality HEAD
语义），不是配置层或小补丁能覆盖的，故挂起。

## 复验方法（下一个 sing-box 大版本更新时执行）

前置：节点仓已含本修复（reality replace 指向 icodex/reality@a32241e），
起一个 xray 内核 REALITY 节点（如 node 7，端口 10007）。

1. 从新版本 fork 构建客户端 CLI：
   `go build -tags "with_quic,with_utls" -o sing-box ./cmd/sing-box`（sing-box 仓根）
2. 客户端配置（socks 入站 12007）：

   ```json
   {
     "inbounds": [{"type":"socks","listen":"127.0.0.1","listen_port":12007}],
     "outbounds": [{
       "type": "vmess", "server": "127.0.0.1", "server_port": 10007,
       "uuid": "<用户uuid>", "security": "auto",
       "tls": {"enabled": true, "server_name": "www.microsoft.com", "insecure": true,
               "utls": {"enabled": true, "fingerprint": "chrome"},
               "reality": {"enabled": true, "public_key": "<面板下发pbk>", "short_id": "0123abcd"}}
     }],
     "route": {"final": "proxy"}
   }
   ```

3. `curl -x socks5h://127.0.0.1:12007 https://www.google.com` 返回 200 = 关闭本 issue。
4. 若仍失败，抓特征：`reality verification failed` = 客户端校验层未同步；
   连接超时 = 记录流仍不兼容（即当前状态）。

## 临时替代

xray 内核客户端，或 mihomo（≥ v1.19.x）。
