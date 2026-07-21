# prefer_domain

`prefer_domain` is an A/AAAA response post-processor backed by a plugin-private
preferred-domain cache. The request path never resolves a preferred domain:
`Exec` only reads the cache entry keyed by preferred domain and QTYPE.

The normal flow is:

1. A resolver or `fallback` produces the client's response.
2. `prefer_domain` checks address records of the requested type against its IP
   matcher rules.
3. If the first matching rule has a usable cached preferred-domain answer for
   the same QTYPE, the matched owner's complete A or AAAA RRset is replaced.
4. If that cache entry is cold or unusable, the original response is returned
   unchanged. Client requests never wait for an on-demand preferred lookup.

Preferred-domain A and AAAA answers are stored separately in each plugin
instance. They do not use or populate mosdns' ordinary response cache.

## Configuration

```yaml
- tag: prefer_domain_cf
  type: prefer_domain
  args:
    resolver: smartdns_direct
    timeout: 500          # milliseconds
    cache_ttl: 301        # required seconds; internal TTL and refresh window
    warm_on_start: true
    serve_stale: true
    max_stale: 3600       # seconds; 0 means unlimited
    rules:
      - ip_matcher: geoip:cloudflare
        prefer_domain: preferred.example
```

`ip_matcher` can reference any plugin implementing `IPMatcherProvider`,
including `ip_set` and `si_set`. Rules are checked in configuration order and
the first matching rule wins. Legacy `ip_set`, `ip_set_tag`, and `ipset` rule
field names remain aliases of `ip_matcher`.

Use it after an ordinary resolver:

```yaml
- exec:
    - $smartdns_direct
    - $prefer_domain_cf
```

It can also process the response selected by `fallback`, without knowing which
branch won:

```yaml
- exec:
    - $fallback
    - $prefer_domain_cf
```

`fallback` treats a branch's `exit` as a successful local control signal when
that branch produced a response, copies the winning context, and returns
normally. The following post-processing action therefore still runs.

If a tagged resolver is itself a sequence whose `exit` propagates directly,
wrap that call with `try` or place `prefer_domain` after an existing outer
`try`, rather than changing the global `exit` semantics:

```yaml
- exec: try $resolve_sequence
- exec: $prefer_domain_cf
```

The configured preferred-domain `resolver` should be a lower-level resolver or
sequence that does not depend on this same `prefer_domain` instance. Internal
preferred-domain queries are marked so accidental re-entry safely skips the
post-processor.

## Warming, refresh, and internal TTL

Background warming starts only after mosdns has finished loading all plugins,
so tagged resolvers are ready before the first preferred-domain query.

With `warm_on_start: true`, every distinct preferred-domain and QTYPE pair is
warmed. A timeout, network/resolver error, missing response, or SERVFAIL is
treated as transient: the initial warming cycle retries every 15 seconds, for
10 attempts in total. NXDOMAIN, NOERROR without an address of the requested
type (NODATA), and other non-transient DNS results are not retried during that
initial cycle. If all attempts are exhausted, the entry stays cold (or retains
its previous value). The exhaustion time is used as the origin of the next
`cache_ttl`-derived refresh window.

With `warm_on_start: false`, that first-ever warming cycle (including its
transient-error retry policy) is delayed until the first refresh window derived
from `cache_ttl`. Later periodic windows use the two-attempt policy described
below.

Periodic refresh performs at most two lookups per entry per window; it does not
run the startup retry loop. If the first lookup fails for any reason, the second
lookup starts immediately. A successful lookup atomically replaces the entry.
If both lookups fail, the old entry is retained rather than cleared.

`cache_ttl` is required, is interpreted in seconds, and must be greater than
`5`. It is the sole source of both the plugin-private internal TTL and the
background refresh window; DNS answer TTLs never determine the internal cache
lifetime. `timeout` must be greater than `0` and less than `2.5` seconds, so
both bounded periodic attempts can fit inside the five-second refresh headroom.

After a successful lookup, the next refresh time is:

```text
stored + cache_ttl - 5s
```

This schedules refresh exactly five seconds before the internal entry expires.
After two periodic failures, later recovery windows remain anchored to the old
entry's `stored` time and advance by whole `cache_ttl` periods. Missed windows
are skipped rather than replayed. If no old entry exists because initial warming
exhausted all 10 attempts, the exhaustion time acts as the window origin.

After two failed periodic attempts, the retained entry remains fresh until its
internal lifetime naturally expires. Once expired, `serve_stale: true` allows
it to continue replacing matching responses with a client-visible TTL of `0`;
with `serve_stale: false`, the original client response is left unchanged. No
synchronous recovery lookup is made. A stale entry remains eligible until a
later window succeeds, subject to `max_stale`; once that limit is exceeded, the
original client response is left unchanged.

The client-visible replacement TTL remains the TTL from the preferred DNS
answer and is aged by the cache entry's elapsed lifetime. A stale replacement
always has a client-visible TTL of `0`.

## Replacement and failure behavior

Only a successful NOERROR response for a single IN A/AAAA question is
eligible. Matching is restricted to address records of the requested type,
including final addresses after a CNAME chain.

On replacement, the original Question, CNAME chain, unrelated Answer records,
authority/additional sections, rcode, and upstream EDNS information are kept.
The replaced owner name's address RRset is swapped atomically; an invalidated
RRSIG covering that RRset is removed, and AA/AD are cleared because the new
RRset is synthesized.

The plugin is a no-op and preserves the current response for:

- no current response;
- non-A/AAAA or non-IN questions;
- NXDOMAIN, SERVFAIL, REFUSED, and other non-NOERROR client responses;
- responses without a matching address;
- a cold preferred-domain cache;
- a cached result without an address of the requested type; or
- an expired entry that is not eligible under `serve_stale` and `max_stale`.

The removed `original_resolver`, `original_timeout`,
`exit_on_original_failure`, and `reuse_original_response` options belonged to
the former pre-resolution mode and must be removed from configurations.
