# Cache 主动刷新

`active_refresh` 按每条缓存的实际 TTL 动态安排刷新，不再周期性扫描缓存。调度模型为一个调度
goroutine、一个可复用 timer、按 `refreshAt` 排序的未来任务堆、按 `expireAt` 排序的有界 pending
堆，以及固定 worker 池。

```yaml
- tag: cache_all
  type: cache
  args:
    size: 10240
    lazy_cache_ttl: 86400
    enable_ecs: true
    dump_file: cache.dump
    dump_interval: 600

    # 命中任意规则后不写入缓存。domain_sets 可引用 domain_set、
    # domain_set_light、sd_set、sd_set_light 等实现 DomainMatcherProvider 的插件。
    exclude_domain:
      exps:
        - domain:fakeip.local
      domain_sets:
        - fakeip_domains
        - fakeip_sd_set
      files:
        - mosdns_cache/no_cache_domain.txt

    active_refresh:
      enabled: true
      # 重启加载 dump 后，自动恢复仍符合条件的主动刷新任务。
      # 未配置或 false 时只恢复缓存内容，真实访问后再为该条目建立刷新任务。
      restore_on_startup: true

      # 最大提前量。实际窗口由 TTL 动态缩短。
      threshold: 60
      # 0 表示不限制空闲时间；未配置时默认为 3600 秒。
      max_idle_time: 3600
      requery_timeout_ms: 1000

      workers: 16
      max_refresh_qps: 30
      refresh_burst: 60
      max_tasks_per_batch: 256
      max_pending_tasks: 2048
      max_retry_times: 2
      max_refresh_times: 0

      exclude_ip:
        cidrs:
          - 198.18.0.0/15
          - 1.1.1.1
          - 2606:4700:4700::1111
        ip_sets:
          - geoip:cloudflare
        files:
          - mosdns_cache/no_active_refresh_ip.txt

      exclude_domain:
        exps:
          - domain:fakeip.local
        domain_sets:
          - fakeip_domains
        files:
          - mosdns_cache/no_active_refresh.txt

      fallback_probe:
        enabled: true
        timeout_ms: 500
        stale_extend_ttl: 60
        max_stale: 300
        probes:
          - tcp:443
          - tcp:8443
          - tcp:80
          - ping
```

## TTL 与重试

普通缓存的刷新时间为：

```text
base_window   = min(threshold, original_ttl / 3)
safety_window = min(original_ttl / 2, 2s)
refresh_window = min(threshold, max(base_window, safety_window))
refresh_at = expire_at - refresh_window
```

`refresh_window` 必须严格大于 0 且小于原 TTL。TTL 为 0、已经过期或无法得到有效 TTL 的响应不会
创建普通 DNS 主动刷新任务（符合条件的私有 retained 条目仍可在到期后进入 fallback probe）。
30、60、90、300 秒 TTL 分别约在写入后 20、40、60、240 秒刷新。

失败重试按剩余寿命计算：

```text
retry_delay = max(500ms, min(remaining / 3, refresh_window / 2))
actual_timeout = min(requery_timeout_ms, remaining / 2, 1000ms)
```

剩余预算不足时停止普通重试；启用 fallback 时，任务在旧答案到期后按配置顺序探测，单次探测
超时不会超过剩余总预算。探测成功只在 `max_stale` 绝对截止时间内续期。

## 并发与队列

- `workers` 是同时执行的 DNS 刷新上限，最大 256。
- `max_refresh_qps` 是长期平均速率，`refresh_burst` 是令牌桶最多积累的突发令牌数。
- `max_pending_tasks` 限制已经到期、等待 worker/令牌的任务数。
- pending 任务按 `expireAt` 排序；队列满时淘汰已失效任务以及过期最晚的低紧急任务。
- `max_tasks_per_batch` 只限制调度器一次转移的到期任务数，不绕过上述限制。
- 每次写入都会产生新的 generation；旧 generation、已淘汰、过期、排除或不活跃任务在消耗
  QPS 和 worker 前丢弃。同一 key/generation 与 lazy 更新共用 inflight 去重。
- 只有真实客户端访问该 key 才更新时间和重置 `max_refresh_times` 计数；主动刷新不会让无人使用的条目
  永久保持活跃。

指标 `cache_active_refresh_events_total{event=...}` 提供 `scheduled`、`executed`、`success`、
`failed`、`retried`、`probe_success`、`probe_failed`、`stale_generation`、`duplicate_inflight`、
`inactive_skipped`、`excluded_domain_skipped`、`excluded_ip_skipped`、`expired_before_run`、
`insufficient_time`、`rate_limited`、`queue_dropped` 和 `dump_restored_tasks` 事件。

## `exclude_ip`

旧列表格式仍受支持，并等价于结构化格式的 `cidrs`：

```yaml
exclude_ip:
  - 198.18.0.0/15
  - 30.0.0.0/8
  - 2001:2::/64
```

`cidrs` 支持 IPv4、IPv6、CIDR 和单 IP；单 IP分别按 `/32`、`/128` 编译。`files` 在初始化时
读取一次，支持 UTF-8 BOM、LF/CRLF、空行、整行及行尾 `#` 注释，错误会包含配置字段、文件名和
行号。相对路径以声明该 cache 插件的配置文件目录为基准。

`ip_sets` 引用已经加载且实现 `data_provider.IPMatcherProvider` 的插件。provider 必须写在 cache
之前；初始化时解析并缓存 matcher，运行期不会重复查找插件。`cidrs`、`files`、`ip_sets` 是 OR
关系；Answer 中任意标准 A/AAAA 命中即停止该缓存的主动刷新。CNAME、空应答、NXDOMAIN、NODATA
和 SERVFAIL 不会误判。

## dump 与关闭

dump 继续保存正常缓存，并额外保存最后真实访问时间和连续主动刷新成功次数。恢复时重新分配
generation、复验排除/活跃规则、按 TTL 重算 `refreshAt`；已经进入刷新窗口的条目加入 0～5 秒
启动抖动，随后仍受 batch、pending、worker 和 QPS 限制。

启用 `restore_on_startup` 后，sequence 在配置编译时自动把 cache 后面的规则链绑定给 cache，dump
任务可在启动时直接重建，不需要独立刷新 sequence，也不需要等待第一次真实查询。一个启用该开关
的 cache 只能出现在一条 sequence 中；多重绑定会作为配置错误拒绝启动，避免恢复任务走错上游。
未启用时只加载缓存内容，后续真实访问仍会按正常逻辑为对应条目建立主动刷新任务。彻底过期、仅靠
lazy 保留的条目不会自动恢复主动刷新。

关闭时先取消生命周期 context、停止调度器和 timer，再等待 worker/dump goroutine，清空 future、
pending、metadata 和待绑定的恢复状态，最后保存 dump。任务 channel 不会被关闭后继续写入。

## 不兼容字段

以下字段已经删除，不再兼容：

```yaml
interval
min_refresh_interval
max_entries_per_scan
refresh_sequence
```

配置出现这些字段会分别返回明确的迁移错误。使用 `max_tasks_per_batch` 控制单批规模；失败间隔和
正常刷新时间均由当前 TTL 动态计算。

普通缓存命中、客户端 TTL 扣减、lazy cache、顶层 `exclude_ip`（禁止写入缓存）以及 fallback 的
有界 serve-stale 语义保持不变。
