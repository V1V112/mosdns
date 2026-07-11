# prefer_domain

`prefer_domain` is an A/AAAA response post-processor. It never resolves the
client-requested name and does nothing until an earlier plugin has populated
`qCtx.R()`.

The normal flow is:

1. Domain rules select a resolver or `fallback`.
2. That resolver produces the final response.
3. `prefer_domain` checks address records of the requested type against its IP
   matcher rules.
4. On the first matching rule, it resolves that rule's preferred domain and
   replaces the matched owner name's complete A or AAAA RRset.
5. A miss or any preferred-query failure leaves the existing response intact.

## Configuration

```yaml
- tag: prefer_domain_cf
  type: prefer_domain
  args:
    resolver: smartdns_direct
    timeout: 500          # milliseconds
    warm_interval: 300    # seconds; 0 disables periodic warming
    cache_ttl: 0          # milliseconds; 0 derives it from the answer
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
preferred-domain queries are marked so an accidental re-entry safely skips the
post-processor.

## Replacement and failure behavior

Only a successful NOERROR response for a single IN A/AAAA question is
eligible. Matching is restricted to address records of the requested type,
including final addresses after a CNAME chain.

On replacement, the original Question, CNAME chain, unrelated Answer records,
authority/additional sections, rcode, and upstream EDNS information are kept.
The replaced owner name's address RRset is swapped atomically; an invalidated
RRSIG covering that RRset is removed, and AA/AD are cleared because the new
RRset is synthesized.

The plugin is a no-op for:

- no current response;
- non-A/AAAA or non-IN questions;
- NXDOMAIN, SERVFAIL, REFUSED, and other non-NOERROR responses;
- responses without a matching address;
- preferred-domain timeouts, resolver errors, non-NOERROR responses, or a
  missing address of the requested type.

The removed `original_resolver`, `original_timeout`,
`exit_on_original_failure`, and `reuse_original_response` options belonged to
the former pre-resolution mode and must be removed from configurations.
