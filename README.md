# xboard-node

Node backend for [Xboard](https://github.com/cedar2025/Xboard). Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria/Hysteria2, TUIC, AnyTLS, Naive, SOCKS, HTTP, Mieru
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/icodex/xboard-node:latest
```

### Docker Compose

```bash
git clone -b compose --depth 1 https://github.com/icodex/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd)

```bash
# Preferred: keep the token out of argv (visible in ps and shell history).
install -m 600 /dev/null /root/xboard-token
printf '%s' 'TOKEN' > /root/xboard-token

# Node mode
curl -fsSL https://raw.githubusercontent.com/icodex/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com \
  --token-file /root/xboard-token --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/icodex/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com \
  --token-file /root/xboard-token --machine-id 1

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token-file /root/xboard-token --node-id 1
xbctl bind add-machine --panel URL --token-file /root/xboard-token --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format.

Legacy identity overrides (`apiHost`/`apiKey`/`nodeID`, `DOMAIN`, `MACHINE_TOKEN`, …) apply only to a legacy single-instance config. In `instances:` mode they are ignored (with a warning) so each instance keeps its own panel identity; shared knobs (`KERNEL_TYPE`, `LOG_LEVEL`) still apply, and per-instance `token_env` references still work. Note that `sudo` drops the environment: use `sudo -E` (or `env_keep`) when relying on `XBOARD_TOKEN`. `kernel.type` accepts `singbox`, `xray` or `auto` (kernel picked per node protocol/transport). See `config.yml.example` for the full field reference.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)
- Protocol/kernel support matrix: [docs-protocol-support.md](docs-protocol-support.md)

## License

MPL-2.0.
