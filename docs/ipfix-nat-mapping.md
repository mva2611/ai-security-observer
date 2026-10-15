# GoFlow2 2.2.6 NAT mapping

`collector/goflow2-mapping.yaml` is derived from the upstream GoFlow2 v2.2.6
`cmd/goflow2/mapping.yaml`. Its expected SHA-256 is:

```text
9e0e900da48e51ed4e1ca0dba5e36403e6fd20e25ba258d2799b6368eb8d4a5f
```

It adds IPFIX Information Elements 225–228 as nullable JSON fields while
listing every built-in FlowMessage output field. The upstream
`time_received_ns: datetimenano` renderer is intentionally omitted so the
existing numeric timestamp contract is preserved.

| IE | JSON field |
|---:|---|
| 225 | `post_nat_src_addr` |
| 226 | `post_nat_dst_addr` |
| 227 | `post_napt_src_port` |
| 228 | `post_napt_dst_port` |

Run the isolated regression against the verified PCAP and an official GoFlow2
v2.2.6 binary:

```sh
python3 tests/validate_ipfix_nat.py \
  --pcap /tmp/mikrotik-ipfix.pcap \
  --goflow2 /tmp/goflow2-2.2.6-darwin-arm64
```

The test replays only to ephemeral loopback UDP sockets. It compares the
unmapped and mapped JSON contracts and independently decodes template 258 to
compare every NAT tuple.

## `template error` in the test capture

The PCAP begins with 15 data sets using template 258 before the first template
258 definition appears in packet 16. GoFlow2 correctly reports
`ErrorTemplateNotFound` for those sets. Its receiver message rate limiter emits
10 visible `template error` warnings, then mutes the remainder. The first data
set after the template definition is decoded normally.

The warning count is identical with and without the custom mapping, so it is
not caused by NAT fields. It is an artifact of starting the capture between
RouterOS template refreshes. Those initial 15 data sets cannot be decoded from
this truncated capture; a long-running collector retains refreshed templates
in memory after receiving them.
