# Cache 主动刷新

`active_refresh` 使用按条目到期调度，不会周期性遍历并锁住整个缓存。后台刷新与
`lazy_cache` 共用同一套按 key 去重，且只有在原缓存版本仍然有效时才允许写回。

生产配置由 `WeakDecode` 解析，`active_refresh` 和 `fallback_probe` 必须使用完整映射，
不要写成布尔标量简写：

```yaml
- tag: cache_all
  type: cache
  args:
    size: 10240
    lazy_cache_ttl: 86400
    enable_ecs: true
    active_refresh:
      enabled: true
      # 可选。推荐指向一个只负责解析、不会记录客户端副作用的 sequence。
      refresh_sequence: resolve_for_cache
      threshold: 60
      interval: 30
      requery_timeout_ms: 5000
      workers: 16
      max_entries_per_scan: 256
      max_refresh_times: 0
      max_idle_time: 3600
      min_refresh_interval: 30
      exclude_ip:
        - 198.18.0.0/15
      exclude_domain:
        exps:
          - domain:fakeip.local
        domain_sets:
          - fakeip_domains
      fallback_probe:
        enabled: false
        timeout_ms: 60
        stale_extend_ttl: 60
        max_stale: 300
        probes:
          - tcp:443
          - tcp:80
          - ping
```

字段说明：

- `threshold`：在到期前多少秒进入刷新窗口；短 TTL 会自动限制为原 TTL 的三分之一。
- `interval`：兼容字段，作为调度抖动上限的参考周期；调度本身按条目精确执行。
- `requery_timeout_ms`：单次后台查询超时。
- `workers`：主动刷新 worker 数，最大 256。
- `max_entries_per_scan`：一次到期批次最多派发的任务数。
- `max_refresh_times`：两次真实客户端访问之间允许的最大刷新次数，`0` 表示不限制。
- `max_idle_time`：超过该秒数没有真实访问的条目停止跟踪。
- `min_refresh_interval`：失败、去重冲突或队列繁忙后的最短重试间隔。
- `refresh_sequence`：可选的专用刷新 sequence。未设置时会重放 cache 后面的链路。
- `fallback_probe.max_stale`：旧答案从原始到期时间起允许保留的绝对上限；探测续期不会突破该值。

安全语义：

- 后台查询的 `SERVFAIL`、`REFUSED`、超时和真实执行错误不会覆盖仍健康的答案。
- 前台 miss 也使用观察版本提交：慢请求不能覆盖期间已经写入的新答案；有私下保留的健康答案时，
  `SERVFAIL` 不会破坏后续 fallback 所需的数据。
- `/flush` 会递增缓存代次，flush 前已经排队或执行中的后台任务不能重新填充缓存。
- `/load_dump` 会先在锁外按条目数和解码大小上限完整校验，再短暂加锁应用、切换缓存代次，
  并清空旧 L1 与主动刷新 metadata，避免慢上传阻塞正常写入或导入后继续命中旧视图。
- fallback 仅作为有界 serve-stale 使用：健康答案在到期前不会被降级；原始数据会在后台私有保留到
  `max_stale` 截止点供探测使用，但不会因此越过 `lazy_cache_ttl` 对外返回。探测成功后的 stale
  响应 TTL 最多 5 秒并清除 AD 位，且不会写入 dump。
- lazy 与主动刷新都会标记为内部刷新；内置限流器不扣客户端令牌，`query_summary` 不重复记录。
- 查询中已经存在的 ECS 会自动进入 key，并按掩码后的网络前缀规范化。如果启用了 `enable_ecs`
  但 ECS 插件位于 cache 之后，会退化为按完整客户端地址隔离，保证正确性但降低命中率；因此仍应
  把写入 ECS 的插件放在 cache 之前。客户端地址不可用或 ECS 无法安全规范化时会直接绕过缓存。

可观测指标包括刷新总数、成功/失败/探测续期/丢弃数、刷新耗时、队列长度和 metadata 数量。

由于缓存 key 新增了 RD、QCLASS 和规范化 ECS，dump 格式已升级到 v3；旧 v2 dump 会被忽略并在
下一次保存时重建。
