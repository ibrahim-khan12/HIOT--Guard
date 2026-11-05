'use strict';
const $ = id => document.getElementById(id);
const titles = {
 inventory: ['Asset inventory', 'A clear view of the endpoints observed across your hospital network.'],
 detail: ['Endpoint profile', 'Observed facts, configured context and a traceable history.'],
 communications: ['Communications', 'Understand who an endpoint talks to, and inspect the supporting evidence.'],
 health: ['Evidence and health', 'Understand the source, freshness and boundaries of your observations.']
};
const icons = {
 grid: '<rect x="3" y="3" width="5" height="5" rx="1"/><rect x="12" y="3" width="5" height="5" rx="1"/><rect x="3" y="12" width="5" height="5" rx="1"/><rect x="12" y="12" width="5" height="5" rx="1"/>',
 activity: '<path d="M2 10h4l2-6 4 12 2-6h4"/>',
 registry: '<rect x="4" y="3" width="12" height="14" rx="2"/><path d="M7 7h6m-6 3h6m-6 3h3"/>',
 flows: '<rect x="2" y="7" width="5" height="6" rx="1"/><rect x="13" y="7" width="5" height="6" rx="1"/><path d="M7 10h6M10 3v4m0 6v4"/>',
 endpoint: '<rect x="4" y="3" width="12" height="10" rx="2"/><path d="M7 17h6m-3-4v4M7 8h2l1-2 1 4 1-2h2"/>',
 server: '<rect x="4" y="2" width="12" height="16" rx="2"/><path d="M4 7h12M4 12h12m-9-8h1m-1 5h1m-1 5h1"/>',
 group: '<circle cx="10" cy="5" r="2"/><circle cx="4" cy="15" r="2"/><circle cx="16" cy="15" r="2"/><path d="M10 7v3m-6 3v-3h12v3"/>',
 shield: '<path d="m10 2 6 3v5c0 4-3 6-6 8-3-2-6-4-6-8V5l6-3Z"/><path d="m7 10 2 2 4-4"/>'
};
let offset=0,next=null,asset=null,selectedAsset=null,commOffset=0,commNext=null,historyOffset=0,historyNext=null;
let comms=[],evidence=[],dataset=[],status=null,inventoryTicket=0,datasetTicket=0,selectionTicket=0,currentView='inventory',searchTimer;
function node(type,cls,text){const n=document.createElement(type);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=text;return n;}
function icon(key){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');for(const [k,v] of Object.entries({viewBox:'0 0 20 20',fill:'none',stroke:'currentColor','stroke-width':'1.3','stroke-linecap':'round','stroke-linejoin':'round','aria-hidden':'true'}))s.setAttribute(k,v);s.innerHTML=icons[key]||icons.endpoint;return s;}
function tag(text,tone=''){return node('span','tag '+tone,text);}
function human(value){
 const map={observed_transmitting:'Transmitting',addressed_only:'Addressed only',unresolved:'Unresolved',multiple_exchange_labels_review_context:'Multiple exchange labels',multiple_macs_on_configured_direct_link:'Multiple MACs on a direct link',multiple_configured_registry_records:'Multiple registry records',configured_direct_link:'Configured direct link',unresolved_link_observation:'Link observation only',physical_device_identity:'Physical device identity',device_category:'Device category',mac_not_available:'MAC address not available',not_recently_observed:'Outside recency window',recently_observed:'Within recency window',unicast_address:'Unicast address',multicast_group:'Multicast group',unspecified:'Unspecified address'};
 return map[value]||String(value||'Not available').replaceAll('_',' ');
}
function date(t,short=false){return Number.isFinite(t)?new Intl.DateTimeFormat('en-GB',short?{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}:{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date(t*1000)):'Not recorded';}
function number(n){return Number(n||0).toLocaleString('en-GB');}
function facts(rows,wide=false){const dl=node('dl','fact-list'+(wide?' wide':''));for(const [label,value,mono] of rows)dl.append(node('dt','',label),node('dd',mono?'mono':'',value===null||value===undefined||value===''?'Not available':String(value)));return dl;}
function technical(value,label='Technical record'){const d=node('details');d.append(node('summary','',label),node('pre','',JSON.stringify(value,null,2)));return d;}
function empty(title,copy){const div=node('div','empty');div.append(icon('endpoint'),node('strong','',title),node('p','',copy));return div;}
function endpointName(a){const r=a.configured?.records?.[0];return r?.name||r?.label||(r?.role?human(r.role):a.address_kind==='multicast_group'?'Multicast group':a.ip.includes(':')?'IPv6 endpoint':'Unregistered endpoint');}
function scopeName(scope){return scope.startsWith('acceptance-')?'Reference capture · '+scope.slice(-6):scope.startsWith('live-')?'Live recording · '+scope.slice(-6):scope.includes('fixture')?'UI verification fixture':human(scope);}
async function get(path){const r=await fetch(path);if(!r.ok)throw Error((await r.json()).error||'Request failed ('+r.status+')');return r.json();}
function safe(task){return async(...args)=>{try{$('error').textContent='';await task(...args);}catch(e){$('error').textContent='Unable to load this view. '+e.message;}};}
function show(view){if(!titles[view])return;currentView=view;for(const k of Object.keys(titles))$(k).hidden=k!==view;document.querySelectorAll('[data-view]').forEach(b=>b.setAttribute('aria-current',b.dataset.view===view?'page':'false'));$('pageTitle').textContent=titles[view][0];$('breadcrumbView').textContent=titles[view][0];$('pageSubtitle').textContent=titles[view][1];}
function filters(){const p=new URLSearchParams();for(const [id,key] of [['search','q'],['scope','scope'],['presence','presence'],['registered','registered'],['review','review']])if($(id).value)p.set(key,$(id).value);return p;}
function inputLabel(){return ({imported_snapshot:'Saved capture',connected:'Input connected',degraded:'Input degraded',unavailable:'Input unavailable',not_connected:'No input connected'})[status?.input?.state]||'Source information';}
async function health(refreshDataset=true){
 status=await get('/api/status');$('inputState').textContent=inputLabel();$('inputState').className='status-pill'+(status.input.state==='unavailable'?' red':status.input.state==='degraded'?' amber':'');$('flowCount').textContent=number(status.canonical_flow_count);
 const chosen=$('scope').value,scopes=[...new Set(status.synchronizations.map(s=>s.scope))];
 $('scope').replaceChildren(new Option('All recordings',''),...scopes.map(s=>new Option(scopeName(s),s)));$('scope').value=scopes.includes(chosen)?chosen:'';$('scope').title=chosen||'All observation recordings';
 const offline=status.input.state==='imported_snapshot';
 $('sourceNote').replaceChildren(node('strong','',offline?'Recorded dataset. ':status.input.state==='connected'?'Passive input connected. ':'Observation source. '),document.createTextNode(offline?'You are viewing saved observations, not live network activity.':status.input.state==='connected'?'Inventory updates from Module 2; no active scans are performed.':'Stored inventory remains available when the monitoring input is unavailable.'));
 renderHealth();if(refreshDataset)await loadDataset();
}
async function loadDataset(){
 const ticket=++datasetTicket,records=[];let cursor=0;
 do{const p=new URLSearchParams({limit:'200',offset:String(cursor)});if($('scope').value)p.set('scope',$('scope').value);const r=await get('/api/assets?'+p);if(ticket!==datasetTicket)return;records.push(...r.records);cursor=r.next_offset;}while(cursor!==null);
 dataset=records;renderSummary();
}
function renderSummary(){
 const registered=dataset.filter(a=>a.configured.records.length).length,transmitting=dataset.filter(a=>a.presence==='observed_transmitting').length,groups=dataset.filter(a=>a.address_kind==='multicast_group').length;
 $('assetCount').textContent=number(dataset.length);$('transmittingCount').textContent=number(transmitting);$('registeredCount').textContent=number(registered);$('assetFoot').textContent=groups?number(groups)+' multicast group · not a device count':'Address entries, not a physical-device count';$('registeredFoot').textContent=number(dataset.length-registered)+' addresses without a registry match';
 const counts=new Map();dataset.forEach(a=>a.protocols.forEach(p=>counts.set(p,(counts.get(p)||0)+1)));
 const entries=[...counts].sort((a,b)=>b[1]-a[1]);entries.push(['Not identified',dataset.filter(a=>!a.protocols.length).length]);$('protocolChart').replaceChildren();
 for(const [label,count] of entries){const row=node('div','bar-row'),title=node('div','bar-label');title.append(node('span','',label),node('b','',number(count)));const track=node('div','bar-track'),fill=node('div','bar-fill');fill.style.width=(dataset.length?count/dataset.length*100:0)+'%';if(label==='Not identified')fill.style.background='#c9d7de';track.append(fill);row.append(title,track);$('protocolChart').append(row);}
 const percent=dataset.length?Math.round(registered/dataset.length*100):0;$('coveragePercent').textContent=percent+'%';const known=node('span'),unknown=node('span');known.style.width=percent+'%';unknown.style.width=(100-percent)+'%';$('coverageBar').replaceChildren(known,unknown);$('coverageKnown').textContent=number(registered)+' matched';$('coverageUnknown').textContent=number(dataset.length-registered)+' unregistered';
 const scopes=[...new Set(dataset.map(a=>a.scope))];$('scopeTitle').textContent=scopes.length===1?scopeName(scopes[0]):number(scopes.length)+' observation recordings';$('scopeMode').textContent=status.input.state==='imported_snapshot'?'Saved observation history':'Passive observation';
 const first=dataset.length?dataset.reduce((v,a)=>Math.min(v,a.first_seen),Infinity):null,last=dataset.length?dataset.reduce((v,a)=>Math.max(v,a.last_seen),0):null;$('scopeContext').replaceChildren();
 for(const [key,value] of [['Capture begins',date(first,true)],['Last observation',date(last,true)],['Presence basis','Packet counters'],['Discovery method','Passive']]){const row=node('div','context-row');row.append(node('span','',key),node('span','',value));$('scopeContext').append(row);}
 $('footerContext').textContent='Flow totals cover all stored recordings · Times shown in your local timezone';
}
async function inventory(){
 const ticket=++inventoryTicket,p=filters();p.set('limit','25');p.set('offset',String(offset));const r=await get('/api/assets?'+p);if(ticket!==inventoryTicket)return;
 next=r.next_offset;$('resultCount').textContent=number(r.total);$('assetRows').replaceChildren();
 for(const a of r.records){
  const tr=node('tr');tr.dataset.id=a.asset_id;const td=node('td'),wrap=node('div','endpoint-cell'),symbol=node('span','endpoint-icon');symbol.append(icon(a.address_kind==='multicast_group'?'group':['pacs','ehr'].includes(a.configured.records[0]?.role)?'server':'endpoint'));
  const identity=node('div'),button=node('button','asset-name',endpointName(a));button.title=a.ip;button.setAttribute('aria-label','Open '+a.ip);button.addEventListener('click',safe(()=>select(a.asset_id)));identity.append(button,node('span','asset-ip mono',a.ip));wrap.append(symbol,identity);td.append(wrap);tr.append(td);
  const presence=node('td'),state=node('span');state.append(node('span','presence-dot'+(a.presence!=='observed_transmitting'?' amber':'')),document.createTextNode(human(a.presence)));presence.append(state);
  if(a.address_kind==='multicast_group')presence.append(node('span','cell-sub','Multicast group'));else if(a.review_findings.length){const review=node('span','cell-sub','Context to review');review.prepend(node('span','review-dot'));review.title=a.review_findings.map(human).join('; ');presence.append(review);}tr.append(presence);
  const protocols=node('td'),list=node('div','protocol-list');if(a.protocols.length)a.protocols.forEach(p=>list.append(tag(p,p==='DICOM'?'blue':'teal')));else list.append(node('span','muted','Not identified'));protocols.append(list);tr.append(protocols);
  const registry=node('td');registry.append(tag(a.configured.records.length?'Matched':'Unregistered',a.configured.records.length?'teal':'outline'));if(a.configured.records.length)registry.append(node('span','cell-sub','IP-based association'));tr.append(registry);
  const connections=node('td');connections.append(node('span','cell-number',number(a.flow_count)),node('span','cell-sub',number(a.peer_count)+' peers'));tr.append(connections);
  const seen=node('td');seen.append(node('span','',date(a.last_seen,true)),node('span','cell-sub',a.activity.anchor==='capture_time'?'Capture time · estimate':human(a.activity.state)));tr.append(seen);$('assetRows').append(tr);
 }
 if(!r.records.length){const tr=node('tr'),td=node('td');td.colSpan=6;td.append(empty('No matching endpoints','Try another search or clear your filters.'));tr.append(td);$('assetRows').append(tr);}
 $('pageLabel').textContent='Showing '+number(r.total?offset+1:0)+'–'+number(offset+r.records.length)+' of '+number(r.total)+' addresses';$('prev').disabled=offset===0;$('next').disabled=next===null;
}
function renderProfile(a){
 $('detailEmpty').hidden=true;$('detailContent').hidden=false;
 const hero=$('endpointHero'),symbol=node('span','endpoint-icon');symbol.append(icon('endpoint'));const heading=node('div');heading.append(node('h2','',endpointName(a)),node('span','mono muted',a.ip));const badges=node('div','protocol-list');badges.append(tag(human(a.presence),'teal'));a.protocols.forEach(p=>badges.append(tag(p,'blue')));const commButton=node('button','btn','View communications →');commButton.addEventListener('click',()=>show('communications'));hero.replaceChildren(symbol,heading,badges,commButton);
 $('facts').replaceChildren(facts([['Network address',a.ip,true],['Address type',human(a.address_kind)],['Presence',human(a.presence)],['First observed',date(a.first_seen)],['Last observed',date(a.last_seen)],['Recorded flows',number(a.flow_count)],['Unique peers',number(a.peer_count)],['Transports',a.transports.join(', ').toUpperCase()],['Protocol participation',a.protocols.join(', ')||'Not established'],['Capture sources',a.observation_sources.join(', ')]]));
 $('facts').append(node('div','divider'),node('h3','subhead','Observed ports'));const ports=node('div','chip-list');a.local_ports.slice(0,12).forEach(p=>ports.append(tag(p[0].toUpperCase()+' / '+p[1],'outline')));if(!a.local_ports.length)ports.append(node('span','muted','No TCP/UDP port information'));$('facts').append(ports);
 if(a.local_ports.length>12){const more=node('details');more.append(node('summary','','View all '+number(a.local_ports.length)+' local ports'),node('p','fact-note',a.local_ports.map(p=>p[0]+'/'+p[1]).join(', ')));$('facts').append(more);}
 $('facts').append(node('p','fact-note','Observation times are derived from flow start and duration. They are not exact last-packet timestamps. Protocol participation does not establish a device model.'));
 $('configured').replaceChildren();
 if(!a.configured.records.length)$('configured').append(node('p','identity-note','No configured registry match. This endpoint remains unregistered; no role or clinical criticality has been inferred.'));
 else{a.configured.records.forEach(r=>{const item=node('div','registry-entry');item.append(facts([['Configured name',r.name||r.label||human(r.role)],['Role',human(r.role)],['Network zone',human(r.zone)],['Clinical criticality',r.critical===true?'Safety-critical (configured)':r.critical===false?'Noncritical (configured)':'Not configured'],['Match method','IP-based registry association']]));$('configured').append(item);});$('configured').append(node('p','fact-note','Supplied by the authorized registry. An IP match is not authenticated device identity.'));}
 const uncertain=node('div','identity-note');uncertain.append(node('strong','','Physical identity is unverified'),node('p','','Device category and model have not been established by this module. Observed protocols and configured labels remain separate.'));$('unknown').replaceChildren(uncertain);
 if(a.review_findings.length){$('unknown').append(node('div','divider'),node('h3','subhead','Context to review'));a.review_findings.forEach(f=>$('unknown').append(node('p','fact-note',human(f)+'. Inspect the supporting exchange before drawing a conclusion.')));}
 $('macFacts').replaceChildren();if(!a.mac_observations.length)$('macFacts').append(node('p','muted','No MAC evidence is available in these records.'),node('p','fact-note','Older monitoring exports may not contain Ethernet fields. Missing data is kept unknown.'));
 else{a.mac_observations.forEach(m=>{const item=node('div','registry-entry');item.append(facts([['MAC address',m.mac,true],['Observation source',m.observation_source],['Association',human(m.association)]]));$('macFacts').append(item);});$('macFacts').append(node('p','fact-note','A routed Ethernet address may identify a next hop. Only explicitly configured direct-link context supports a device association.'));}
 $('commEndpoint').textContent=endpointName(a)+' · '+a.ip;$('commSummary').replaceChildren();for(const [label,value] of [['recorded flows',a.flow_count],['unique peers',a.peer_count],['evidence-backed protocols',a.protocols.length]]){const span=node('span');span.append(node('b','',number(value)),document.createTextNode(label));$('commSummary').append(span);}
}
async function select(id){
 const ticket=++selectionTicket;asset=id;commOffset=0;historyOffset=0;$('commSearch').value='';$('detailContent').hidden=true;$('detailEmpty').hidden=false;$('detailEmpty').replaceChildren(empty('Loading endpoint profile','Retrieving stored observations and evidence…'));show('detail');
 const a=await get('/api/assets/'+id);if(ticket!==selectionTicket)return;selectedAsset=a;renderProfile(a);await Promise.all([history(ticket),communications(ticket)]);
}
async function history(ticket=selectionTicket){
 if(!asset)return;const r=await get('/api/events?asset_id='+asset+'&limit=8&offset='+historyOffset);if(ticket!==selectionTicket)return;historyNext=r.next_offset;$('history').replaceChildren();
 const labels={discovered:'Endpoint first discovered',returned:'Endpoint observed again',profile_updated:'Observation profile updated',registry_changed:'Configured registry changed',observations_corrected:'Observation profile corrected',observations_withdrawn:'Supporting observations withdrawn',upstream_flow_updated:'Flow evidence updated',upstream_flow_withdrawn:'Flow withdrawn by monitoring'};
 for(const e of r.records){const item=node('div','timeline-item');item.append(node('div','timeline-title',labels[e.kind]||human(e.kind)),node('div','timeline-time',date(e.at)));const f=e.data.current_flow||e.data.previous_flow;item.append(node('p','timeline-copy',f?f.source_ip+' → '+f.destination_ip+' · '+f.transport.toUpperCase()+(f.destination_port?' / '+f.destination_port:''):e.kind==='discovered'?'Created from captured communication, independently of registry configuration.':'Previous state is preserved in the audit record.'));item.append(technical(e.data,'Inspect event provenance'));$('history').append(item);}
 if(!r.records.length)$('history').append(node('p','muted','No change events are available.'));$('historyLabel').textContent=number(r.total)+' recorded events';$('historyPrev').disabled=historyOffset===0;$('historyNext').disabled=historyNext===null;
}
async function communications(ticket=selectionTicket){
 if(!asset)return;const p='/api/assets/'+asset+'/',params='?limit=20&offset='+commOffset;const [c,e]=await Promise.all([get(p+'communications'+params),get(p+'evidence'+params)]);if(ticket!==selectionTicket)return;comms=c.records;evidence=e.records;commNext=c.next_offset;
 $('commLabel').textContent='Showing '+(c.total?commOffset+1:0)+'–'+(commOffset+comms.length)+' of '+number(c.total)+' flows';$('commPrev').disabled=commOffset===0;$('commNext').disabled=commNext===null;renderComms();
}
function addressCell(ip,port){const td=node('td');td.append(node('span','mono',ip),node('span','cell-sub',port===null||port===undefined?'No transport port':'Port '+port));return td;}
function renderComms(){
 const q=$('commSearch').value.toLowerCase();$('commRows').replaceChildren();
 comms.forEach((f,i)=>{if(q&&!JSON.stringify(f).toLowerCase().includes(q))return;const tr=node('tr');tr.append(addressCell(f.source_ip,f.source_port),addressCell(f.destination_ip,f.destination_port));const transport=node('td');transport.append(tag(f.transport.toUpperCase(),'outline'));tr.append(transport);const outcome=node('td'),label={SF:'Established',S0:'No reply observed',S1:'Established / open',REJ:'Rejected',RSTO:'Origin reset',RSTR:'Responder reset'}[f.connection_state]||'Recorded: '+(f.connection_state||'unknown');outcome.append(tag(label,f.connection_state==='SF'?'teal':f.connection_state==='S0'?'amber':'outline'));tr.append(outcome);const packets=node('td','packet-pair');packets.append(document.createTextNode(f.origin_packets??'?'),node('span','','/'),document.createTextNode(f.response_packets??'?'));tr.append(packets);const td=node('td'),button=node('button','inline-link','Inspect evidence ↗');button.addEventListener('click',()=>openEvidence(evidence[i],f));td.append(button);tr.append(td);$('commRows').append(tr);});
 if(!$('commRows').children.length){const tr=node('tr'),td=node('td');td.colSpan=6;td.append(empty(asset?'No matching connections on this page':'Choose an endpoint first',asset?'Try another search or browse older flows.':'Open an address in Inventory to inspect its communications.'));tr.append(td);$('commRows').append(tr);}
}
function openEvidence(proof,flow){
 const c=$('flowEvidence');c.replaceChildren();const intro=node('div','evidence-card');intro.append(node('h3','','Observed connection'),node('div','divider'),facts([['Origin',flow.source_ip+(flow.source_port?' / '+flow.source_port:'')],['Responder',flow.destination_ip+(flow.destination_port?' / '+flow.destination_port:'')],['Observed at',date(flow.start_time)],['Correlation',human(flow.correlation_status)]],true));c.append(intro);
 const captures=node('div','evidence-card');captures.append(node('h3','','Capture provenance'));
 for(const cap of proof.captures){const item=node('div','evidence-event');item.append(tag(cap.raw_retained===true?'Raw capture retained':cap.raw_retained===false?'Raw capture unavailable':'Retention not established',cap.raw_retained?'teal':'amber'),node('p','evidence-ref','Capture ID · '+cap.capture_id));if(cap.sha256)item.append(node('p','evidence-ref','SHA-256 · '+cap.sha256));if(!cap.raw_retained)item.append(node('p','fact-note','The analytical reference is preserved. Availability of the original packet bytes is not established.'));captures.append(item);}c.append(captures);
 const protocol=node('div','evidence-card');protocol.append(node('h3','','Packet-backed protocol evidence'));const metadata={calling_ae:'Calling AE title',called_ae:'Called AE title',abstract_syntax:'Abstract syntax',sender:'HL7 sender',message_type:'Message type'};
 if(!proof.protocol_evidence.length)protocol.append(node('p','fact-note','No validated medical protocol metadata is attached to this flow. A service port alone is not confirmation.'));
 for(const e of proof.protocol_evidence){const item=node('div','evidence-event');item.append(node('div','event-label',e.protocol+' · Frame '+e.frame),facts([['Parser status',human(e.parser_status)],['Packet time',date(e.timestamp)],...Object.entries(e.metadata||{}).map(([k,v])=>[metadata[k]||human(k),v]),...(e.supporting_frames?[['Supporting frames',e.supporting_frames.join(', ')]]:[])],true));protocol.append(item);}c.append(protocol);
 if(proof.link_layer_evidence.length){const mac=node('div','evidence-card');mac.append(node('h3','','Ethernet observations'));for(const e of proof.link_layer_evidence){const item=node('div','evidence-event');item.append(facts([['MAC address',e.mac,true],['Frame / source',e.frame+' / '+e.observation_source],['Ethernet direction',human(e.ethernet_direction)],['Association','Link observation; inspect capture context']],true));mac.append(item);}c.append(mac);}
 c.append(technical(proof,'Full technical evidence record'));if(!$('evidenceDialog').open)$('evidenceDialog').showModal();
}
function renderHealth(){
 const input=status.input;$('healthBadge').textContent=inputLabel();$('healthBadge').className='tag '+(['unavailable','degraded'].includes(input.state)?'amber':'blue');const head=node('div','health-head'),symbol=node('span','health-icon');symbol.append(icon('shield'));const title=node('div');title.append(node('h3','',input.state==='imported_snapshot'?'Saved monitoring observations':'Module 2 passive monitoring'),node('p','','Inventory is preserved independently of browser activity.'));head.append(symbol,title);
 $('healthData').replaceChildren(head,facts([['Source mode',inputLabel()],['Last successful sync',date(input.last_success)],['Last input check',date(input.checked_at)],['Collector state',input.state==='imported_snapshot'?'Not running for this saved dataset':human(input.collector?.state)],['Upstream',input.url||'Explicit offline import']]));
 if(input.error)$('healthData').append(node('p','identity-note',input.error));$('healthData').append(node('p','fact-note','An input outage does not establish that any endpoint is offline. Recency is based on available observations.'),technical(input,'Input diagnostics'));
 $('syncData').replaceChildren();for(const s of status.synchronizations){const item=node('div','registry-entry');item.append(node('h3','',scopeName(s.scope)),node('p','fact-note','Last committed '+date(s.at)),facts([['Input mode',s.mode==='imported_snapshot'?'Imported snapshot':'Consistent monitoring snapshot'],['Recording scope',s.scope,true]]),technical({source:s.source,revision:s.revision,digest:s.digest},'Snapshot integrity'));$('syncData').append(item);}if(!status.synchronizations.length)$('syncData').append(node('p','muted','No snapshots have been committed yet.'));
 $('silentCount').textContent=number(status.configured_unobserved.length);$('silent').replaceChildren();for(const e of status.configured_unobserved){const item=node('div','silent-item'),records=Array.isArray(e.configured)?e.configured:[e.configured],info=node('div');info.append(node('div','silent-name',records.map(r=>r.name||r.label||human(r.role)).join(' / ')),node('div','silent-ip mono',e.ip));item.append(info,tag('Not observed','outline'));$('silent').append(item);}if(!status.configured_unobserved.length)$('silent').append(node('p','muted','No additional configured entries are unobserved in the stored recordings.'));
 const limits=['Passive visibility: only endpoints mentioned in monitored traffic can appear. A silent device may remain undiscovered.','Identity boundaries: a registry match, DICOM association or HL7 exchange does not authenticate a physical device or establish its model.','Inherited monitoring limits: Module 2 did not pass its historical strict sustained acceptance. Capture completeness and zero packet loss are not established.'];$('limitations').replaceChildren();limits.forEach((text,i)=>{const row=node('div','limit');row.append(node('span','number','0'+(i+1)),node('span','',text));$('limitations').append(row);});
}
document.querySelectorAll('[data-view]').forEach(b=>{b.setAttribute('aria-label',({inventory:'Inventory',detail:'Endpoint details',communications:'Communications',health:'Evidence and health'})[b.dataset.view]);b.addEventListener('click',()=>show(b.dataset.view));});
document.querySelectorAll('[data-open-inventory]').forEach(b=>b.addEventListener('click',()=>show('inventory')));
document.querySelectorAll('[data-open-health]').forEach(b=>b.addEventListener('click',()=>show('health')));
document.querySelectorAll('[data-icon]').forEach(n=>n.append(icon(n.dataset.icon)));
$('topbarDate').textContent=new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'long',year:'numeric'}).format(new Date());
$('filterToggle').addEventListener('click',()=>{$('extraFilters').hidden=!$('extraFilters').hidden;$('filterToggle').setAttribute('aria-expanded',String(!$('extraFilters').hidden));});
$('search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(safe(async()=>{offset=0;await inventory();}),180);});
for(const id of ['scope','presence','registered','review'])$(id).addEventListener('change',safe(async()=>{offset=0;await Promise.all([inventory(),id==='scope'?loadDataset():Promise.resolve()]);}));
$('clearFilters').addEventListener('click',safe(async()=>{for(const id of ['search','presence','registered','review'])$(id).value='';offset=0;await inventory();}));
$('refresh').addEventListener('click',safe(async()=>{$('refresh').disabled=true;try{await health();await inventory();if(selectedAsset){selectedAsset=await get('/api/assets/'+asset);renderProfile(selectedAsset);await Promise.all([history(),communications()]);}}finally{$('refresh').disabled=false;}}));
$('next').addEventListener('click',safe(async()=>{if(next===null)return;offset=next;await inventory();}));
$('prev').addEventListener('click',safe(async()=>{offset=Math.max(0,offset-25);await inventory();}));
$('commSearch').addEventListener('input',renderComms);
$('commNext').addEventListener('click',safe(async()=>{if(commNext===null)return;commOffset=commNext;await communications();}));
$('commPrev').addEventListener('click',safe(async()=>{commOffset=Math.max(0,commOffset-20);await communications();}));
$('historyNext').addEventListener('click',safe(async()=>{if(historyNext===null)return;historyOffset=historyNext;await history();}));
$('historyPrev').addEventListener('click',safe(async()=>{historyOffset=Math.max(0,historyOffset-8);await history();}));
$('closeEvidence').addEventListener('click',()=>$('evidenceDialog').close());
$('evidenceDialog').addEventListener('click',e=>{if(e.target===$('evidenceDialog')&&e.clientX<$('evidenceDialog').getBoundingClientRect().left)$('evidenceDialog').close();});
$('export').addEventListener('click',()=>{const a=document.createElement('a');a.href='/api/export.jsonl?'+filters();a.download='hiot-guard-inventory.jsonl';a.click();});
renderComms();safe(async()=>{await health();await inventory();})();
setInterval(safe(async()=>{await health(currentView==='inventory');if(currentView==='inventory')await inventory();}),15000);
