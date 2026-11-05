# Module 3: Evidence-Based Asset Discovery and Inventory

Module 1 generates hospital lab traffic. Module 2 observes and normalizes it.
Module 3 maintains a persistent, explainable inventory from those observations.
Its worker is independent of the browser. It performs no network scanning,
device-category inference, threat scoring, or firewall enforcement.

The Module 3 numbering and boundary were approved for this implementation:
discovery and inventory now; separately evaluated device identity/classification
later. The earlier pipeline document described stages without fixing this numbering.

## Architecture

```text
Module 1 hospital testbed, port 8877
  -> Module 2 passive capture and processing, port 8878
     -> versioned canonical flows + capture/protocol/link-layer evidence
        -> consistent discovery snapshot
           -> validation and temporary SQLite staging
              -> transactional inventory reconciliation
                 -> persistent endpoint profiles + communications + audit history
                    -> Module 3 read-only API and views, port 8879
                    -> future identity / detection / risk consumers
```

The module uses Python's standard library; no additional runtime dependency is
required beyond the repository environment. Runtime databases and evidence live
under ignored `runs/`. Do not commit PCAPs, databases, credentials or run manifests.

## Running it

From the repository root, with Module 2 already serving:

```powershell
.\.venv\Scripts\python.exe -m module3 serve
# Or: & ".\Module 3\run-module3.cmd"
# Limit integration to a particular recording:
.\.venv\Scripts\python.exe -m module3 serve --scope <recording-scope>
```

Open `http://127.0.0.1:8879/`. This does not start GNS3, a VM, hospital actors, or
Module 2 capture. If Module 2 is unavailable, input health says unavailable and
the inventory remains intact. `Ctrl+C` shuts down the discovery service.

Explicit offline import of an existing canonical Module 2 JSONL export:

```powershell
.\.venv\Scripts\python.exe -m module3 import runs/module2/acceptance-report.jsonl --legacy --source-id saved-hospital --scope acceptance-1792060858677683600
.\.venv\Scripts\python.exe -m module3 serve --offline
.\.venv\Scripts\python.exe -m module3 status
.\.venv\Scripts\python.exe -m module3 export runs/module3/inventory.jsonl
```

Use a stable `--source-id` for repeat imports from the same source. A legacy
import replaces only the explicitly selected source/scope, must contain at least
one matching record, and cannot establish capture retention if metadata is absent.
Use framed snapshots for deliberate empty-scope reconciliation.

Import a complete framed snapshot without `--legacy`; its header supplies identity,
scope and revision. A source's identity is a database-instance UUID, not an
authenticated hardware identity. Copying a database retains that identity; to
represent a genuinely independent deployment, provision a separate state database.

Global CLI flags precede the command:

```powershell
.\.venv\Scripts\python.exe -m module3 --state runs/my-inventory --registry registry.json --direct-links direct-links.json --activity-window 300 serve --interval 5
```

The default registry is `config.registry('gns3')`. A custom registry JSON maps IPs
to a record or list of records. Multiple configured records are retained for
review. A direct-link JSON maps an observation source to the IP explicitly known
to be directly attached, for example `{"pump": "10.77.20.20"}`. There is no implicit
binding based on source names. Supply these same configuration flags on restart.

## Inventory semantics

| Field/state | Meaning |
|---|---|
| `asset_id` | SHA-256 of source-instance ID, scope and normalized IP |
| `observed_transmitting` | Directional packet counters show transmitted traffic |
| `addressed_only` | Responder address with zero observed reply packets |
| `unresolved` | Available directional information cannot establish presence |
| `address_kind` | Unicast address, multicast group, or unspecified address |
| `first_seen` / `last_seen` | Minimum flow start / maximum start+duration estimate |
| `local_ports` / `peer_ports` | Observed transport/port sets; connection direction remains in communications |
| `protocols` | Participation in a parser-confirmed exchange; not inferred device type |
| `mac_observations` | Link-context observations; full provenance is in evidence |
| `configured.records` | Registry information, separately attributed to operator configuration |
| `review_findings` | Context needs inspection; not an attack verdict |
| `current=false` | Supporting upstream observations were withdrawn; historical profile remains accessible |

An inventory count is a count of address entries, not a count of physical devices.
A multicast group is not a medical device. One physical device can use multiple
IPs; one IP can be reused by multiple devices. Scope separation prevents unrelated
experiments being merged. Link-local IP reuse across different capture domains
still needs stronger context before making physical-identity claims.

Flow byte/packet counters inherit Module 2 canonical selection; overlapping links
are not summed. Unmatched upstream observations are not proven unique sessions.
Packet retransmissions are handled upstream, not guessed from equal IP/port pairs.

A port is a service hint, not protocol proof. DICOM AE titles and HL7 senders are
exchange metadata and can be user-controlled. They are not manufacturer/model
identification or clinical criticality. Multiple exchange labels are retained with
their flow evidence; a label variation is not automatically a contradiction.

Live scopes (`live-...`) use wall-clock recency; other scopes use the latest flow
time in the capture. The default recency window is 300 seconds. “Not recently
observed” never means “offline,” especially during an upstream outage.

## MAC extension in Module 2

The optional `link_layer_evidence` array supplements `hiot.monitoring.v1`:
MAC, Ethernet direction, network source/destination IP, capture/observation IDs,
observation source, first/last supporting frame and timestamp, and association
status. Groups are per flow/link/direction/address combination. Historical TSVs
without the two Ethernet columns remain parseable; older flows may omit the array.

MAC evidence is extracted during Module 2's existing analysis, not by a second
Module 3 collector. Module 2 canonical selection retains evidence across its
supporting observations. Historical cached analyses do not magically gain MACs:
explicit Module 2 reanalysis is needed.

Across a router, an Ethernet MAC can identify a next hop. Only an explicit trusted
direct-link configuration permits a `configured_direct_link` association. This is
still an observed/configured association, not authenticated identity or spoofing
resistance. Otherwise the association is `unresolved_link_observation`.

## Module 2 snapshot contract

* `GET /api/discovery-revision`: `hiot.monitoring.snapshot.v1`, persistent source ID,
  integer revision, available scopes. The revision is global to the database;
  changes in another scope can cause a harmless extra snapshot.
* `GET /api/discovery-snapshot.jsonl?scope=...`: explicit scope required; streams a
  header, capture envelopes, canonical-flow envelopes, and completion trailer.

The header contains schema/source/scope/revision. Payload envelopes are
`{"type":"capture"|"flow","record":{...}}`. The trailer contains type `complete`,
payload-envelope count, SHA-256 of the exact payload-envelope lines including
newlines, and matching revision. The hash detects truncation/corruption; it is not
an authentication signature. A single SQLite read transaction covers the stream.

Flow imports, capture insert/update/delete, archival paths and raw-expiry metadata
invalidate discovery revisions. Health is polled separately every worker cycle so
a collector outage remains visible without changing flow content.

Module 3 validates a complete snapshot in temporary on-disk SQLite before touching
inventory. Unsupported schemas, invalid addresses/counters/timestamps/ports,
duplicate flow IDs, bad provenance, checksum mismatch, or missing trailer reject
the entire replacement. Lines are bounded at 8 MiB. Snapshots larger than available
temporary storage fail visibly; previous inventory remains intact.

Stable IDs and content hashes reconcile additions, updates and removals. Volatile
Zeek UIDs do not cause profile changes. Updated old flows are reconsidered even
when their original start timestamp is unchanged. Flow corrections/withdrawals
retain their previous records in audit events. Projection and synchronization
checkpoint commit together, so a crash cannot publish half an inventory.

The worker downloads a full changed-scope snapshot but updates only changed flow
contributions and affected profiles. This is not an unbounded-throughput streaming
architecture: snapshot transfer/validation scales with scope size, and projecting
a busy endpoint scales with its current flow history. Stress measurements must
describe this limit. Analytical/event history has no automatic destructive pruning;
operators must provide storage/retention planning.

## Module 3 API

### Operator workspace

The interface uses a sidebar with Inventory, Endpoint details, Communications,
and Evidence and health views. Summary cards and protocol bars use stored
observations; address/presence/registry summaries follow the selected recording.
The canonical-flow card covers all stored recordings, as labelled in the footer.
Search and advanced filters apply to the inventory table and its export.

Profiles keep observed facts, configured registry information and unresolved
identity in separate cards. History is a readable timeline. Evidence opens in a
side panel with capture IDs, retained-byte status, protocol metadata and supporting
frames; full JSON is optional under a disclosure. The interface identifies
imported snapshots as saved observations rather than live activity.

All endpoints bind to loopback; no arbitrary file-read/import or control API is
exposed. Responses use `hiot.discovery.v1` except the lightweight readiness probe.
The dashboard renders data as text and uses a same-origin script policy.

| GET path | Parameters and behaviour |
|---|---|
| `/api/ready` | Readiness, independent of upstream availability |
| `/api/status` | Counts, sync checkpoints, input health, configured-but-unobserved entries and inherited limits |
| `/api/assets` | `q`, `scope`, `source_id`, `presence`, `registered=0|1`, `review=0|1`, `limit=1..200`, `offset` |
| `/api/assets/{id}` | Attributed endpoint profile, including a withdrawn historical profile |
| `/api/assets/{id}/communications` | Flow relationships, state and directional packet counts; bounded flow pages |
| `/api/assets/{id}/evidence` | Matching canonical-flow evidence groups and capture-retention references; bounded flow-group pages |
| `/api/events` | Optional `asset_id`, bounded `limit`/`offset` pages |
| `/api/export.jsonl` | Complete streamed inventory using the same inventory filters |

List responses include `records`, `total`, and `next_offset` where applicable.
Evidence pagination counts canonical-flow evidence groups, not individual frames.
Exports hold a consistent SQLite snapshot; a slow HTTP client has a 30-second socket
timeout. Capture availability is reported from Module 2 metadata. An offline import
without metadata says unknown, never retained. No arbitrary PCAP download endpoint
is provided. Use the capture IDs and frame references in the authorized evidence
folder to inspect bytes separately.

## Verification and presentation

See `MODULE3_EVALUATION.md` for measured results and limitations. Repeatable tools:

```powershell
.\.venv\Scripts\python.exe -m unittest test_module2 test_module2_hardening test_live -v
.\.venv\Scripts\python.exe -m unittest discover -s "Module 3/tests" -v
.\.venv\Scripts\python.exe "Module 3/tools/verify_module3.py" --monitoring-db runs/module2-hardening-20261018/acceptance-state/monitoring.sqlite3 --scope acceptance-1792340111388501600 --expected-tcp 368 --output runs/module3-evaluation/offline-final
.\.venv\Scripts\python.exe "Module 3/tools/verify_module3_mac.py"
.\.venv\Scripts\python.exe "Module 3/tools/verify_module3_browser.py"
.\.venv\Scripts\python.exe "Module 3/tools/evaluate_module3_service.py" --seconds 900 --flows 10000 --output runs/module3-evaluation/service-final.json
```

Browser verification requires Node, Playwright and an installed Chrome, with
`RUNTIME_NODE_MODULES` set if Playwright is supplied by the bundled runtime. The
browser runner serves a copy of saved inventory plus a separately named synthetic
scope for pagination and nonresponse cases; it shuts down its own server afterward.
The service evaluator uses synthetic canonical records through actual local HTTP
APIs. It does not measure Zeek, packet loss, physical devices, or threat detection.

For the viva, show a registered pump endpoint, distinguish its configured role from
observed HL7 participation, inspect a supporting flow/capture/frame, import the same
snapshot again without extra counts, correct an older flow, and disconnect only
the local test input to show that history survives. Use the automated tests for
the synthetic nonresponding-address case, without generating extra hospital traffic.

The research/engineering contribution is evidence-preserving reconciliation of
overlapping, evolving passive observations into endpoint knowledge, with explicit
uncertainty and measurable acceptance. A unique-IP list cannot establish reply
presence, provenance, configured/observed separation, or correction history.

Module 2's strict sustained acceptance remains false in its recorded 905.6-second
run (10/90 degraded samples). Module 3 cannot recover unseen traffic or establish
zero loss. Fresh Linux-sensor MAC acceptance and GNS3 end-to-end testing remain a
separately arranged live phase. No VM is started by these offline/API checks.

## Source organization

Module 3 source and support files live under Module 3/. Its module3/ directory
contains the implementation and UI; tests/, tools/ and docs/ hold the verification
and documentation. The small root module3/__init__.py forwards imports to that
implementation, preserving python -m module3. Run commands above from the checkout
root. Runtime runs/ paths and preserved historical evidence are unchanged.
