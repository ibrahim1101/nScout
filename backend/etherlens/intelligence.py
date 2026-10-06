"""nScout packet/connection intelligence helpers."""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple
from .protocol_intelligence import tls_intelligence, packet_timeline
from .security_intelligence import security_intelligence
from .host_intelligence import host_intelligence

TCP_PROTOCOLS = {"TCP", "HTTP", "HTTPS", "TLS", "SSH", "FTP", "SMTP", "SMTPS", "POP3", "POP3S", "IMAP", "IMAPS"}

def _layer(packet: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    for layer in packet.get("layers", []):
        if str(layer.get("name", "")).lower().startswith(prefix.lower()): return layer.get("fields", {}) or {}
    return {}
def _endpoint_key(ip: str, port: Any) -> Tuple[str, int]:
    try: return ip or "", int(port or 0)
    except (TypeError, ValueError): return ip or "", 0
def _flow_key(p: Dict[str, Any]): return tuple(sorted((_endpoint_key(p.get("src_ip", ""), p.get("src_port")), _endpoint_key(p.get("dst_ip", ""), p.get("dst_port")))))

def annotate_tcp_health(packets: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out={}; seen_ranges=defaultdict(list); last_seq={}; dup_acks=defaultdict(int)
    for p in sorted(packets,key=lambda x:(x.get("timestamp",0),x.get("number",0))):
        if p.get("protocol") not in TCP_PROTOCOLS: continue
        tcp=_layer(p,"Transmission Control Protocol")
        if not tcp: continue
        src,dst=p.get("src_ip",""),p.get("dst_ip",""); sport,dport=int(p.get("src_port") or 0),int(p.get("dst_port") or 0); direction=(src,sport,dst,dport); flags=str(p.get("flags","")); seq=int(tcp.get("Sequence Number") or 0); ack=int(tcp.get("Acknowledgment Number") or 0); payload=int(p.get("payload_size") or 0); events=[]
        if "RST" in flags: events.append("tcp.reset")
        if int(tcp.get("Window Size") or 0)==0 and "RST" not in flags: events.append("tcp.zero_window")
        if payload:
            end=seq+payload
            if any(seq<e and end>s for s,e in seen_ranges[direction]): events.append("tcp.retransmission")
            elif direction in last_seq and seq<last_seq[direction]: events.append("tcp.out_of_order")
            seen_ranges[direction].append((seq,end)); last_seq[direction]=max(last_seq.get(direction,seq),end)
        if "ACK" in flags and payload==0:
            k=(src,sport,dst,dport,ack); dup_acks[k]+=1
            if dup_acks[k]>=3: events.append("tcp.duplicate_ack")
        if events: out[str(p.get("id"))]={"events":sorted(set(events)),"healthy":False}
    return out

def connection_intelligence(packets: List[Dict[str, Any]], limit: int=500) -> List[Dict[str, Any]]:
    health=annotate_tcp_health(packets); groups={}
    for p in packets:
        if not p.get("src_ip") or not p.get("dst_ip"): continue
        key=_flow_key(p); row=groups.setdefault(key,{"a_ip":key[0][0],"a_port":key[0][1],"b_ip":key[1][0],"b_port":key[1][1],"packets":0,"bytes":0,"a_to_b_bytes":0,"b_to_a_bytes":0,"first_seen":p.get("timestamp",0),"last_seen":p.get("timestamp",0),"protocols":set(),"retransmissions":0,"duplicate_acks":0,"out_of_order":0,"zero_windows":0,"resets":0,"state":"observed"})
        row["packets"]+=1; size=int(p.get("length") or 0); row["bytes"]+=size; row["a_to_b_bytes" if _endpoint_key(p.get("src_ip",""),p.get("src_port"))==key[0] else "b_to_a_bytes"]+=size; row["first_seen"]=min(row["first_seen"],p.get("timestamp",0)); row["last_seen"]=max(row["last_seen"],p.get("timestamp",0)); row["protocols"].add(p.get("protocol","unknown"))
        events=health.get(str(p.get("id")),{}).get("events",[])
        for event,field in (("tcp.retransmission","retransmissions"),("tcp.duplicate_ack","duplicate_acks"),("tcp.out_of_order","out_of_order"),("tcp.zero_window","zero_windows"),("tcp.reset","resets")): row[field]+=int(event in events)
        flags=str(p.get("flags",""))
        if "SYN" in flags and "ACK" not in flags: row["state"]="connecting"
        if "SYN" in flags and "ACK" in flags: row["state"]="established"
        if "FIN" in flags: row["state"]="closing"
        if "RST" in flags: row["state"]="reset"
    rows=[]
    for row in groups.values(): row["duration_ms"]=round(max(0,row["last_seen"]-row["first_seen"])*1000,3); row["protocols"]=sorted(row["protocols"]); rows.append(row)
    return sorted(rows,key=lambda r:(r["bytes"],r["packets"]),reverse=True)[:limit]

def dns_intelligence(packets):
    events=[]; domains=Counter(); failed=Counter()
    for p in packets:
        d=_layer(p,"Domain Name System")
        if not d: continue
        query=str(d.get("Query") or ""); info=str(p.get("info") or ""); domains[query]+=bool(query); is_response="response" in info.lower(); rcode=d.get("Response Code",d.get("RCODE"))
        if rcode not in (None,0,"0","NOERROR") and query: failed[query]+=1
        events.append({"packet_id":p.get("id"),"timestamp":p.get("timestamp"),"src_ip":p.get("src_ip"),"dst_ip":p.get("dst_ip"),"query":query,"response":is_response,"response_code":rcode,"answers":d.get("Answers",[]),"ttl":d.get("TTL")})
    return {"events":events,"top_domains":[{"domain":k,"queries":v} for k,v in domains.most_common(25)],"failed_lookups":[{"domain":k,"failures":v} for k,v in failed.most_common(25)]}

def http_intelligence(packets):
    events=[]; hosts=Counter(); errors=[]
    for p in packets:
        h=_layer(p,"Hypertext Transfer Protocol")
        if not h: continue
        host=str(h.get("Host") or ""); hosts[host]+=bool(host); status=str(h.get("Status") or ""); event={"packet_id":p.get("id"),"timestamp":p.get("timestamp"),"src_ip":p.get("src_ip"),"dst_ip":p.get("dst_ip"),"method":h.get("Method"),"host":host,"path":h.get("Path"),"status":status,"user_agent":h.get("User-Agent"),"server":h.get("Server")}; events.append(event)
        if status.startswith(("4","5")): errors.append(event)
    return {"events":events,"top_hosts":[{"host":k,"requests":v} for k,v in hosts.most_common(25)],"errors":errors}

def device_intelligence(packets):
    devices={}
    for p in packets:
        eth=_layer(p,"Ethernet II"); src_mac=eth.get("Source"); dst_mac=eth.get("Destination")
        for ip,mac,direction in ((p.get("src_ip"),src_mac,"sent"),(p.get("dst_ip"),dst_mac,"received")):
            if not ip: continue
            d=devices.setdefault(str(ip),{"ip":ip,"mac":mac or "","first_seen":p.get("timestamp",0),"last_seen":p.get("timestamp",0),"packets":0,"bytes_sent":0,"bytes_received":0,"protocols":set()})
            if mac and not d["mac"]: d["mac"]=mac
            d["first_seen"]=min(d["first_seen"],p.get("timestamp",0)); d["last_seen"]=max(d["last_seen"],p.get("timestamp",0)); d["packets"]+=1; d["protocols"].add(p.get("protocol","unknown")); d["bytes_sent" if direction=="sent" else "bytes_received"]+=int(p.get("length") or 0)
    out=[]
    for d in devices.values(): d["protocols"]=sorted(d["protocols"]); d["total_bytes"]=d["bytes_sent"]+d["bytes_received"]; out.append(d)
    return sorted(out,key=lambda x:x["total_bytes"],reverse=True)

def protocol_dashboard(packets):
    protocols=Counter(str(p.get("protocol") or "Unknown") for p in packets); ports=Counter(); endpoints=Counter()
    for p in packets:
        if p.get("src_ip"): endpoints[p["src_ip"]]+=int(p.get("length") or 0)
        if p.get("dst_ip"): endpoints[p["dst_ip"]]+=int(p.get("length") or 0)
        for port in (p.get("src_port"),p.get("dst_port")):
            if port: ports[int(port)]+=1
    total=sum(protocols.values()) or 1
    return {"total_packets":len(packets),"total_bytes":sum(int(p.get("length") or 0) for p in packets),"protocols":[{"protocol":k,"packets":v,"percent":round(v*100/total,2)} for k,v in protocols.most_common()],"top_ports":[{"port":k,"packets":v} for k,v in ports.most_common(15)],"top_endpoints":[{"ip":k,"bytes":v} for k,v in endpoints.most_common(15)]}

def investigation_summary(packets, threats):
    connections=connection_intelligence(packets); health=annotate_tcp_health(packets); health_counts=Counter(event for value in health.values() for event in value.get("events",[])); security=security_intelligence(packets, threats)
    return {"overview":protocol_dashboard(packets),"connections":connections[:50],"devices":device_intelligence(packets)[:50],"hosts":host_intelligence(packets, security["findings"])[:100],"dns":dns_intelligence(packets),"http":http_intelligence(packets),"tls":tls_intelligence(packets),"timeline":packet_timeline(packets),"tcp_health":dict(health_counts),"security":security,"threats":threats[:100],"interesting_packets":[{"packet_id":pid,**value} for pid,value in health.items()][:100]}
