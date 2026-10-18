# 职安盾 HTTPS 与生产上线清单

## 1. 上线目标

生产环境至少应满足：

- 独立域名，不使用裸 IP 对外运营
- HTTPS 全站加密，HTTP 自动跳转 HTTPS
- 应用只监听 `127.0.0.1:8000`
- 数据库和证据文件位于 `/opt/veriwork-data`
- Nginx 先拦截敏感路径，再转发到应用
- 每日自动备份数据库与证据文件
- 监控健康检查和磁盘空间
- 有隐私政策、用户协议和账号注销入口

## 2. 域名与备案

在中国大陆服务器上对外提供网站服务，应先完成：

1. 域名实名认证和 DNS 解析
2. ICP 备案
3. 如涉及个人信息处理，准备隐私政策和用户协议
4. 根据实际业务判断是否需要进行个人信息保护影响评估

比赛演示可以继续使用临时 IP，但不要使用真实合同、真实身份证号或真实手机号。

## 3. HTTPS 配置建议

建议使用 Certbot：

```bash
apt-get update
apt-get install -y certbot python3-certbot-nginx
certbot --nginx -d your-domain.example
```

证书生效后修改 `/opt/veriwork/.env`：

```text
SESSION_COOKIE_SECURE=1
SESSION_COOKIE_PATH=/veriwork/
CORS_ORIGIN=
```

重启：

```bash
systemctl restart veriwork
```

验证：

```bash
curl -I https://your-domain.example/veriwork/
curl -s https://your-domain.example/veriwork/api/health
```

## 4. Nginx 安全规则

安装仓库内配置：

```bash
bash /opt/veriwork/deploy/apply-nginx-guard.sh
```

必须保证以下路径返回 `404`：

- `/veriwork/data/veriwork.db`
- `/veriwork/.env`
- `/veriwork/server.py`
- `/veriwork/requirements.txt`
- `/veriwork/docs/`
- `/veriwork/deploy/`
- `/veriwork/tests/`
- `/veriwork/tools/`

## 5. systemd 权限收口

安装新版服务文件：

```bash
install -m 644 /opt/veriwork/deploy/veriwork.service /etc/systemd/system/veriwork.service
systemctl daemon-reload
systemctl restart veriwork
systemctl --no-pager --full status veriwork
```

新服务文件启用：

- `ProtectSystem=strict`
- `ProtectHome=true`
- `PrivateTmp=true`
- `NoNewPrivileges=true`
- `ReadWritePaths=/opt/veriwork-data`
- 禁用全部 Linux capabilities

## 6. 自动备份

安装每日备份：

```bash
bash /opt/veriwork/deploy/install-backup-timer.sh
systemctl list-timers | grep veriwork
```

默认每天 03:30 备份，保留 14 天：

- `/opt/veriwork-data/backups/veriwork-*.db`
- `/opt/veriwork-data/backups/evidence-*.tar.gz`

每季度至少做一次恢复演练，不能只验证“备份文件存在”。

## 7. 监控与告警

最低监控项：

- `/api/health` 是否返回 200
- `databaseOk` 是否为 true
- `evidenceStorageOk` 是否为 true
- 磁盘剩余空间是否大于 20%
- systemd 服务是否处于 active
- Nginx 5xx 比例
- 登录失败次数异常增长
- DeepSeek 调用量和费用异常增长

建议接入 Uptime Kuma、Prometheus Node Exporter 或云厂商监控。

## 8. 上线验收

- [ ] HTTPS 证书有效
- [ ] HTTP 自动跳转 HTTPS
- [ ] 敏感路径全部 404
- [ ] 普通用户无法访问管理员 API
- [ ] 登录 Cookie 带 `HttpOnly`、`Secure`、`SameSite`
- [ ] 修改密码后其他设备退出
- [ ] 管理员可停用、重置、删除用户
- [ ] 审计日志可查询
- [ ] 用户可导出和删除自己的数据
- [ ] 案例档案、报告、证据包可用
- [ ] 自动备份已启用
- [ ] 恢复演练已完成
