# Module 3 evaluation and evidence

Evaluation dates: 5–6 November 2026 (Asia/Karachi). This evaluates an isolated FYP
inventory module, not a hospital deployment, trained device classifier, or threat
detector. Runtime evidence is local under `runs/module3-evaluation/`, outside Git.

## Verification method

Three separate kinds of evidence are used:

1. Deterministic tests exercise discovery, reconciliation, uncertainty and failure
   handling, including actual loopback Module 2/3 HTTP integration.
2. Independent local TShark reads retained hospital PCAP bytes and compares their
   endpoint/presence/peer/port evidence with the inventory produced from the saved
   Module 2 records. A separate compatibility run feeds local Ethernet fields and
   retained Zeek logs through the extended Module 2 parser.
3. Synthetic canonical-flow replay measures service/API performance without
   requiring Zeek, the sensor, hospital actors, or a running VM. Synthetic records
   are explicitly identified and are never called captured hospital traffic.

## Correctness evidence

| Requirement | Result and evidence |
|---|---|
| Module 1/2/3 regressions | 141 tests ran; passed, with one existing real socket/capture integration test skipped. `regressions.txt` |
| Discovery-specific invariants | 27 tests: new/returning addresses, destination-only and unresolved presence, missing/routed/direct MACs, IPv6/UDP/ICMP, registry separation/conflicts, replay, correction/withdrawal history, restart, concurrent snapshot consistency and upstream outage/recovery |
| Saved endpoint agreement | 17 entries for 17 distinct address values; endpoint precision 1.0, recall 1.0. `offline-final/report.json` |
| Presence agreement | Exact match with independent packet-source addresses: 16 transmitting addresses, one addressed-only multicast group |
| Historical TCP reference | 368 TCP canonical records, matching 152 CT + 216 pump-capture connections; **not** 368 endpoints |
| Evidence provenance | 890 protocol evidence entries have valid capture/frame references and matching packet timestamps; three retained capture hashes match |
| Peer/service agreement | Every tested TCP/UDP oriented IP/port tuple has an independent saved-packet reference |
| Duplicate/restart behaviour | Repeated full snapshot adds no flows or discovery events; reopening the inventory preserves counts |
| MAC compatibility | 912 pump + 702 modality grouped link observations match their supporting Ethernet-frame fields, with no normalization findings. `mac/report.json` |
| Operator interface | Eight desktop/mobile browser checks passed, including pagination, keyboard selection, configured/observed separation, capture/frame inspection, a real filtered download, nonresponse display, layout and JavaScript errors. `browser-evidence-final/report.json` |

The saved reference scope is `acceptance-1792340111388501600` in the existing
Module 2 hardening acceptance database. Its 462 canonical records consist of 368
TCP records and 94 ICMP records. The address set contains five IPv4 addresses,
eleven IPv6 link-local addresses, and the IPv6 multicast group `ff02::2`.
These are **17 observed address entries, not 17 physical devices**. Capture-limited
discovery is not expected to reproduce the configured 16-actor topology.

The CT raw hash is
`1dd7c9f7d199c1d3cd13fb59df26728f1065d50d9209a47bfb4213347a7e5443`;
the pump raw hash is
`90c07bf6d5eabb373f8996b30dd644f1fd1de9d6e6fd2bf180e05cea4f895dbe`.
The mirror observation repeats the CT capture; Module 2 correlation prevents
its TCP records being counted twice. Per-capture metadata and schema are saved
with the final snapshot.

The reference decoder is local TShark 4.6.3, separately identified from Module 2's
pinned Linux TShark 4.4.19 / Zeek 8.0.10. The MAC compatibility experiment reused
the saved pinned Zeek logs and regenerated only TShark fields locally. It verifies
the parser/interface path against actual bytes; it does **not** establish fresh
Linux-container toolchain acceptance after the Ethernet-field extension.

## Service experiment

`service-final.json` records the final 10,000-flow, 251-address replay/API experiment,
using the five-second default polling interval. Updated evidence is committed to
an **older** canonical flow so a start-time-only consumer would miss the change.
The independently running worker must publish it before queries see the new label.

This experiment measures **Module 2 database commit → Module 3 query availability**,
not packet arrival → detection latency. Warm inventory/detail requests, working
memory, CPU time, initial synchronization time, errors and source hashes are saved.
Both local APIs run inside the benchmark process, so its CPU/working-memory values
cover that combined harness rather than an isolated Module 3 deployment.
The acceptance checks are a 900-second exercise, consistent inventory, p95 update
delay <=10 seconds, and p95 warm API latency <=1 second. **All four checks passed.**

| Final measured result | Value |
|---|---|
| Timed duration | 900.015 seconds |
| Update/consistency samples | 73 |
| Canonical flows / observed addresses | 10,000 / 251 |
| Initial synchronization | 6.844 seconds |
| Commit-to-inventory update delay, p95 / max | 7.829 / 9.891 seconds |
| Warm inventory/detail API delay, p95 | 0.031 seconds |
| Maximum sampled working memory, combined harness | 50.50 MiB |
| CPU time during timed phase, combined harness | 37.0 seconds |
| Inconsistent counts / recorded input errors | 0 / 0 |

These are development-machine observations at the documented synthetic offered
load, not worst-case bounds. Each cycle changes evidence on one old flow and
queries inventory/detail APIs; it is not a high-rate packet-capture benchmark.
The source hashes in the final report match the evaluated Module 2/3 Python files.
UI text/layout and documentation are verified separately from the service timer.

### Larger-history capacity characterization

`stress.json` records a separate 100,000-flow experiment after sustained acceptance:
all 100,000 records and 251 address entries remained consistent, with no errors.
Initial synchronization took **81.734 seconds**; synchronizing one updated old flow
took **22.203 seconds**; p95 warm inventory/detail API latency was **0.047 seconds**.
The combined harness sampled 104.76 MiB working memory after the operations.

This is an explicit capacity limit: the ten-second update target passed at 10,000
flows but is **not met or claimed at 100,000 flows**. Full changed-scope download
and validation plus recomputing a busy endpoint's profile explain the scaling
cost. A revisioned delta feed or bounded operational scopes are future performance
work; responsive paginated queries alone do not establish rapid synchronization.

To reproduce: `python "Module 3/tools/stress_module3.py" --flows 100000`. This is characterization,
not a second 15-minute acceptance run and not a hospital packet-rate measurement.

## Baseline and experimental limitations

A simple unique-IP list finds the same 17 address values, but cannot distinguish
an unanswered target from a transmitter, attach evidence, separate configured
labels, preserve corrections, or survive restarts as an auditable inventory.
Those additional behaviours are evaluated by tests and the saved-byte comparison;
this is a capability baseline, not a claim of improved classifier accuracy.

The browser runner serves a copy of the saved inventory plus an explicitly named
`demonstration-fixture` scope for pagination/nonresponse coverage. It does not
generate hospital traffic. Screenshots therefore include separately scoped fixture
addresses in global totals; the selected hospital records remain capture-backed.

Preliminary interrupted/failing runs remain in the evidence folder. The first
historical evaluation attempt was denied access to raw captures after committing
its copied inventory. Retrying exposed unstable historical source identity in the
runner, which was corrected to a deterministic saved-source ID. A fresh final
folder checks both distinct addresses and exact inventory entry count. Preliminary
browser runs also caught a navigation race while detail requests were finishing;
the view switches immediately and no longer reverses the user's navigation.

The first replay's Windows memory helper returned invalid zero values; those memory
samples are unusable. The helper was corrected and the final experiment records
valid working-memory samples. Preserve the preliminary run rather than silently
replacing its observations.

No GNS3 VM, Kali VM, or FortiGate VM was started or modified. Fresh live hospital
acceptance remains a separately arranged phase. Module 2's historical strict
sustained run failed, with 10/90 degraded samples, despite p95 snapshot freshness
of 20.54 seconds. Module 3 inherits coverage/freshness limitations and cannot claim
zero packet loss. Offline evidence does not demonstrate physical medical-device
identity, real-patient safety, or hospital-scale performance.

## Requirement-to-evidence map

### Presentation interface update — 6 November 2026

The original console-style interface was replaced with a responsive discovery
workspace: sidebar navigation, data-backed address/presence/registry summaries,
a compact inventory table, protocol-participation bars and recording context.
Endpoint profiles now use readable fact lists, separate configured information
and a chronological audit timeline. Capture/frame evidence opens in a
keyboard-accessible side panel. Technical records remain available inside
expandable disclosures.

The report at runs/module3-ui-review/verification-final/report.json records
**16 passing browser checks**, covering summary agreement with stored data,
pagination, keyboard selection, structured profiles and evidence, Escape dismissal,
filtered downloads, nonresponding targets, advanced filters, empty searches,
desktop/mobile overflow, readable health information and JavaScript errors.
Screenshots cover 1440-pixel desktop and 390-pixel mobile layouts. The preview on
port 8879 continues to use saved hospital records; the isolated UI test ran on
port 8889 with its separately labelled fixture.

The source contracts, discovery engine and stored observations were not changed
by the visual redesign. Existing performance measurements remain service/API
measurements, not benchmarks of the redesigned browser's client-side summaries.

| Behaviour | Repeatable evidence |
|---|---|
| Discover observed endpoints without populating silent registry entries | `InventoryTests.test_both_endpoints_and_silent_registry`, saved capture comparison |
| Avoid declaring probe targets live | `test_target_without_reply_is_not_live`, browser addressed-only filter |
| Unknown identity and cautious MAC associations | `test_missing_mac_and_port_only_hint`, `test_routed_mac_requires_explicit_direct_context`, direct-link conflict test |
| Reconcile replay, updates and withdrawals | Replay/UID, updated-old-flow, evidence-correction and withdrawal tests |
| Persist and preserve provenance | Restart test, saved-frame/hash reference checks, evidence API |
| Reject partial input atomically | Invalid-input and truncated/digest-mismatch snapshot tests |
| Consistent reads during upstream writes | `test_concurrent_write_does_not_mix_snapshot_revisions` |
| Recover independently of a browser | Actual HTTP worker outage/recovery test and service replay experiment |
| Bound list queries and export all matching entries | Pagination/filter/export tests and actual downloaded JSONL |

See `MODULE3.md` for commands and interface definitions. Runtime reports and raw
artifacts remain ignored; source, repeatable tests and this evaluation record are
the reviewable deliverables. Academic acceptance remains the supervisor's decision.

## Repository organization

Source and evaluation tools are now under Module 3/. Historical run paths, logs
and recorded source hashes identify the layout at the time of each experiment;
they have not been rewritten to imply those experiments ran after this move.
The folder migration is checked with discovery/regression tests, browser
verification and standalone tool/launcher checks. See ../README.md for layout.
