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
      # enabled=true 时，重启加载 dump 后自动恢复符合条件的刷新任务；
      # enabled=false 时只恢复缓存内容，不建立刷新任务。

      # 最大提前量。实际窗口由 TTL 动态缩短。
      threshold: 60
      # 0 表示不限制空闲时间；未配置时默认为 3600 秒。
      max_idle_time: 3600

      # 以下 6 项是一组显式启用的热门追踪策略，必须全部填写。
      # 全部省略时保持旧主动刷新行为；只填写一部分会启动失败。
      # 主动刷新独立追踪上限必须大于 0 且不大于 size。
      # 本例普通缓存 10240 条，只追踪其中最热的 2000 条；若 size 为
      # 100000，可按同样思路填 10000。
      max_tracked_entries: 2000
      # 未追踪条目必须在 admission_window 秒内累计到指定真实访问次数，
      # 才保存 replay 并进入主动刷新，推荐填写 2。
      admission_hits: 2
      admission_window: 600
      # 热度每经过这些秒衰减一半；命中路径只写原子计数，不争用全局锁。
      heat_half_life: 600
      # CLOCK 受保护区最多占独立追踪上限的百分比。
      protected_ratio: 80
      # 容量满时一次最多检查多少个索引项，避免全表扫描。
      eviction_scan_limit: 64
      requery_timeout_ms: 1000

      workers: 16
      max_refresh_qps: 30
      # 以下两项省略时随 max_refresh_qps 线性调整；当前 QPS 下分别为 60、256。
      # 显式填写仍可覆盖自动值。
      # refresh_burst: 60
      # max_tasks_per_batch: 256
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

## 热门条目准入与淘汰

这 6 项是一个不可拆分的显式策略组：`max_tracked_entries`、`admission_hits`、`admission_window`、`heat_half_life`、`protected_ratio` 和 `eviction_scan_limit`。全部省略时不启用热门准入、独立追踪上限、热度衰减、CLOCK 二次机会和保护区，主动刷新保持旧行为：第一次真实访问即可追踪、追踪上限等于普通缓存 `size`，容量满时按最不紧迫的到期时间淘汰。全部填写时才启用下述热门策略；只填写一部分会返回缺失字段错误。6 个值都必须大于 `0`，其中 `max_tracked_entries` 还不得大于 `size`，`protected_ratio` 不得大于 `100`。

`max_tracked_entries` 只限制主动刷新保存的 replay、调度元数据和任务，不改变普通 DNS 缓存 `size`。

真实客户端命中会增加条目的原子访问计数。未追踪条目在 `admission_window` 内达到 `admission_hits` 后才创建 replay。已追踪条目通过引用位获得 CLOCK 二次机会，热条目最多按 `protected_ratio` 进入受保护区；容量满时只检查 `eviction_scan_limit` 个索引项，并在这些候选中淘汰衰减热度最低的冷条目。`heat_half_life` 表示热度减半所需秒数。主动刷新、重试、探测和 lazy 后台回放不计为真实访问。dump 会保存准入状态、窗口进度和热度；重启时只为关机前已经通过热门准入且仍符合 TTL、空闲、排除等条件的条目恢复刷新任务，停机时间也会计入热度衰减。

userspace fast_cache 会把同一条目一轮内的真实命中合并成一次权重样本，cache 按该权重增加热度且不会额外再加 1。累计值在下一次过期请求时交给 cache；如果条目或进程在此之前结束，最后尚未触发的一小段尾数不会上报。当前随仓库发布的 kernel eBPF 对象只有旧版 280 字节过期事件，不能上报 5 秒新鲜期内的全部命中，因此 kernel/both 模式暂时只能把一次过期事件视为“至少 1 次活跃”。Go 端已兼容带命中数的 296 字节扩展事件；要获得 kernel 精确计数，还需取回 eBPF C 源码、加入独立计数 Map，并同时重新编译 `combined.o` 与 `xdp_dns.o`。

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
- `max_refresh_qps` 是长期平均速率。省略 `refresh_burst` 时自动取
  `ceil(max_refresh_qps × 60 / 30)`，最小为 1；它表示令牌桶最多积累的突发令牌数。
- `max_pending_tasks` 限制已经到期、等待 worker/令牌的任务数。
- pending 任务按 `expireAt` 排序；队列满时淘汰已失效任务以及过期最晚的低紧急任务。
- 省略 `max_tasks_per_batch` 时自动取
  `min(max_pending_tasks, 2048, max(64, ceil(max_refresh_qps × 256 / 30)))`；它只限制调度器
  一次转移的到期任务数，不绕过上述限制。两项自动值都以原默认 QPS 30 下的 60、256 为基准，
  显式填写时仍以配置值为准。
- 每次写入都会产生新的 generation；旧 generation、已淘汰、过期、排除或不活跃任务在消耗
  QPS 和 worker 前丢弃。同一 key/generation 与 lazy 更新共用 inflight 去重。
- 只有真实客户端访问该 key 才更新时间和重置 `max_refresh_times` 计数；主动刷新不会让无人使用的条目
  永久保持活跃。

指标 `mosdns_cache_active_refresh_events_total{event=...}` 提供 `scheduled`、`executed`、`success`、
`failed`、`retried`、`probe_success`、`probe_failed`、`stale_generation`、`duplicate_inflight`、
`inactive_skipped`、`excluded_domain_skipped`、`excluded_ip_skipped`、`expired_before_run`、
`insufficient_time`、`rate_limited`、`queue_dropped`、`admission_wait`、`admission_ready`、
`admission_capture_deduplicated`、`admitted`、`admission_capacity_rejected`、`clock_promoted`、
`clock_demoted`、`clock_evicted`、`fast_cache_hits_merged` 和 `dump_restored_tasks` 事件。
其中 `fast_cache_hits_merged` 累加被权重样本合并进热度的命中数，不是合并批次数。

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

dump 继续保存全部正常缓存，并额外保存最后真实访问时间、连续主动刷新成功次数，以及带版本的热门
准入窗口、累计命中和衰减热度状态。恢复时重新分配 generation、复验排除/活跃规则、按 TTL 重算
`refreshAt`；已经进入刷新窗口的条目加入 0～5 秒启动抖动，随后仍受 batch、pending、worker 和
QPS 限制。

`active_refresh.enabled: true` 时，sequence 在配置编译时自动把 cache 后面的规则链绑定给 cache，
dump 任务可在启动时直接重建，不需要独立刷新 sequence，也不需要等待第一次真实查询。热门 6 项
未启用时保持原恢复逻辑：为 dump 中全部符合条件的缓存恢复刷新。热门 6 项启用时只恢复 dump 中
关机前已经通过准入的热门条目；普通冷缓存仍会加载，但必须在重启后通过真实访问达到门槛才会开始
刷新。读取没有热门状态的旧版 v3 dump 时同样采用这个保守规则。`active_refresh.enabled: false`
时只加载缓存内容，不创建刷新任务。

一个启用主动刷新的 cache 只能绑定一条 sequence；多重绑定会作为配置错误拒绝启动，避免恢复任务
走错上游。彻底过期、仅靠 lazy 保留的条目不会自动恢复主动刷新。

关闭时先取消生命周期 context、停止调度器和 timer，再等待 worker/dump goroutine；随后在主动刷新
metadata 仍可读取时写入最终 dump，最后清空 future、pending、metadata 和待绑定恢复状态。任务
channel 不会被关闭后继续写入。

## 不兼容字段

以下字段已经删除，不再兼容：

```yaml
interval
min_refresh_interval
max_entries_per_scan
refresh_sequence
restore_on_startup
```

配置出现这些字段会分别返回明确的迁移错误。使用 `max_tasks_per_batch` 控制单批规模；失败间隔和
正常刷新时间均由当前 TTL 动态计算。启动恢复现在直接跟随 `active_refresh.enabled`，不再单独配置。

普通缓存命中、客户端 TTL 扣减、lazy cache、顶层 `exclude_ip`（禁止写入缓存）以及 fallback 的
有界 serve-stale 语义保持不变。
