# GoFlow2 2.2.6 NAT mapping

`collector/goflow2-mapping.yaml` is derived from the upstream GoFlow2 v2.2.6
`cmd/goflow2/mapping.yaml`. Its expected SHA-256 is:

```text
964a63ee79628bc4588cb5c3f075b469bf42af5747476b852f42865402c92ff8
```

It adds IPFIX Information Elements 225–228 as nullable JSON fields while
listing every built-in FlowMessage output field. The upstream
`time_received_ns: datetimenano` renderer is intentionally omitted so the
existing numeric timestamp contract is preserved.

It also preserves RouterOS relative flow timestamps and the device boot epoch:

| IE | JSON field |
|---:|---|
| 21 | `flow_end_sys_uptime_ms` |
| 22 | `flow_start_sys_uptime_ms` |
| 160 | `system_init_time_ms` |

GoFlow2's native `time_flow_start_ns` and `time_flow_end_ns` remain unchanged.
Additional presence markers for IE 150–159 let FlowStore distinguish native
absolute/delta timestamps from GoFlow2's export-time fallback. FlowStore gives
valid native absolute timestamps priority, then reconstructs RouterOS times as
`(system_init_time_ms + flow_*_sys_uptime_ms) * 1_000_000`.

FlowStore rejects reversed intervals, timestamps more than five minutes in the
future, and starts more than 24 hours before receipt. If native and relative
time data are incomplete or invalid, it keeps GoFlow2's valid export-time
fallback; malformed or missing GoFlow2 fallback values are replaced by local
receive time rounded down to one second and remain labelled `export_fallback`.

The 24-hour bound also applies to offline replay. A historical PCAP can contain
complete and valid IE 21/22/160 values, while GoFlow2 assigns a new current
`time_received_ns` during replay. If the reconstructed flow start is then more
than 24 hours before that new receipt time, FlowStore intentionally stores the
record as `export_fallback`. This does not mean the relative IEs were absent or
failed to decode. Use a current-time synthetic packet to test acceptance of
reconstruction, and use historical replay to verify that the real RouterOS
fields reach the collector.

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
