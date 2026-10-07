"""nScout packet capture, dissection, simulation and PCAP ingestion engine."""
from __future__ import annotations
import asyncio, io, os, random, time, uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Packet, rdpcap
from scapy.layers.http import HTTPRequest, HTTPResponse

APP_PORTS={80:"HTTP",8080:"HTTP",443:"HTTPS",8443:"HTTPS",53:"DNS",22:"SSH",21:"FTP",25:"SMTP",587:"SMTP",465:"SMTPS",110:"POP3",143:"IMAP",993:"IMAPS",995:"POP3S",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",27017:"MongoDB",3389:"RDP",5900:"VNC",123:"NTP",161:"SNMP",1883:"MQTT",5060:"SIP",67:"DHCP",68:"DHCP",69:"TFTP",179:"BGP",389:"LDAP",636:"LDAPS",445:"SMB",139:"NetBIOS"}

def _tcp_flags(v:int)->str:
    names=[name for bit,name in ((1,"FIN"),(2,"SYN"),(4,"RST"),(8,"PSH"),(16,"ACK"),(32,"URG"),(64,"ECE"),(128,"CWR")) if v&bit]
    return ",".join(names) if names else "-"
def _decode(v):
    if isinstance(v,bytes): return v.decode(errors="replace")
    return str(v) if v is not None else ""
def _dns_answers(dns):
    out=[]
    try:
        count=int(dns.ancount or 0); rr=dns.an
        for i in range(count):
            item=rr[i] if hasattr(rr,"__getitem__") else rr
            rdata=getattr(item,"rdata",""); rdata=_decode(rdata)
            out.append({"name":_decode(getattr(item,"rrname",b"")).rstrip("."),"type":int(getattr(item,"type",0) or 0),"value":rdata,"ttl":int(getattr(item,"ttl",0) or 0)})
    except Exception: pass
    return out

def dissect_packet(pkt:Packet,number:int,ts:float)->Dict[str,Any]:
    try: pkt=pkt.__class__(bytes(pkt))
    except Exception: pass
    raw=bytes(pkt); layers=[]; src_ip=dst_ip=""; src_port=dst_port=None; protocol="ETH"; info=""; payload_size=0
    layers.append({"name":"Frame","fields":{"Frame Number":number,"Arrival Time":datetime.fromtimestamp(ts,tz=timezone.utc).isoformat(),"Frame Length":f"{len(raw)} bytes","Capture Length":f"{len(raw)} bytes"}})
    if Ether in pkt:
        e=pkt[Ether]; layers.append({"name":"Ethernet II","fields":{"Destination":e.dst,"Source":e.src,"Type":hex(e.type)}})
    if ARP in pkt:
        a=pkt[ARP]; protocol="ARP"; src_ip,dst_ip=a.psrc,a.pdst; op={1:"request",2:"reply"}.get(a.op,str(a.op)); info=f"Who has {a.pdst}? Tell {a.psrc}" if a.op==1 else f"{a.psrc} is at {a.hwsrc}"
        layers.append({"name":"ARP","fields":{"Opcode":op,"Sender MAC":a.hwsrc,"Sender IP":a.psrc,"Target MAC":a.hwdst,"Target IP":a.pdst}})
    if IP in pkt:
        x=pkt[IP]; src_ip,dst_ip=x.src,x.dst; protocol="IPv4"; layers.append({"name":"Internet Protocol v4","fields":{"Version":x.version,"Header Length":f"{(x.ihl or 5)*4} bytes","TOS":hex(x.tos or 0),"Total Length":x.len or 0,"Identification":hex(x.id or 0),"Flags":str(x.flags),"Fragment Offset":x.frag,"TTL":x.ttl,"Protocol":x.proto,"Header Checksum":hex(x.chksum or 0),"Source":x.src,"Destination":x.dst}})
    elif IPv6 in pkt:
        x=pkt[IPv6]; src_ip,dst_ip=x.src,x.dst; protocol="IPv6"; layers.append({"name":"Internet Protocol v6","fields":{"Version":6,"Traffic Class":hex(x.tc),"Flow Label":hex(x.fl),"Payload Length":x.plen,"Next Header":x.nh,"Hop Limit":x.hlim,"Source":x.src,"Destination":x.dst}})
    if TCP in pkt:
        t=pkt[TCP]; src_port,dst_port=int(t.sport),int(t.dport); flags=_tcp_flags(int(t.flags)); payload_size=len(bytes(t.payload)); protocol=APP_PORTS.get(dst_port) or APP_PORTS.get(src_port) or "TCP"; info=f"{src_port} → {dst_port} [{flags}] Seq={t.seq} Ack={t.ack} Win={t.window} Len={payload_size}"
        layers.append({"name":"Transmission Control Protocol","fields":{"Source Port":src_port,"Destination Port":dst_port,"Sequence Number":t.seq,"Acknowledgment Number":t.ack,"Data Offset":int(t.dataofs or 0)*4,"Flags":flags,"Window Size":t.window,"Checksum":hex(t.chksum or 0),"Urgent Pointer":t.urgptr,"Options":[str(v) for v in (t.options or [])],"Payload Size":payload_size}})
    elif UDP in pkt:
        u=pkt[UDP]; src_port,dst_port=int(u.sport),int(u.dport); payload_size=max(0,int(u.len or 8)-8); protocol=APP_PORTS.get(dst_port) or APP_PORTS.get(src_port) or "UDP"; info=f"{src_port} → {dst_port} Len={u.len}"
        layers.append({"name":"User Datagram Protocol","fields":{"Source Port":src_port,"Destination Port":dst_port,"Length":u.len,"Checksum":hex(u.chksum or 0),"Payload Size":payload_size}})
    elif ICMP in pkt:
        i=pkt[ICMP]; protocol="ICMP"; info=f"type={i.type} code={i.code}"; layers.append({"name":"Internet Control Message Protocol","fields":{"Type":i.type,"Code":i.code,"Checksum":hex(i.chksum or 0)}})
    if DNS in pkt:
        d=pkt[DNS]; protocol="DNS"; qname=""; qtype=None
        try:
            if d.qd: qname=_decode(d.qd.qname).rstrip("."); qtype=int(d.qd.qtype)
        except Exception: pass
        answers=_dns_answers(d); rcode=int(d.rcode or 0); info=f"DNS {'response' if d.qr else 'query'} 0x{d.id:04x} {qname}".strip()
        layers.append({"name":"Domain Name System","fields":{"Transaction ID":hex(d.id),"Response":bool(d.qr),"Opcode":int(d.opcode or 0),"Authoritative":bool(d.aa),"Truncated":bool(d.tc),"Recursion Desired":bool(d.rd),"Recursion Available":bool(d.ra),"Response Code":rcode,"Questions":int(d.qdcount or 0),"Answer RRs":int(d.ancount or 0),"Authority RRs":int(d.nscount or 0),"Additional RRs":int(d.arcount or 0),"Query":qname,"Query Type":qtype,"Answers":answers,"TTL":min((a["ttl"] for a in answers),default=None)}})
    try:
        if HTTPRequest in pkt:
            h=pkt[HTTPRequest]; protocol="HTTP"; method=_decode(h.Method); path=_decode(h.Path); host=_decode(h.Host); info=f"{method} {host}{path}"; layers.append({"name":"Hypertext Transfer Protocol","fields":{"Method":method,"Host":host,"Path":path,"URL":f"http://{host}{path}" if host else path,"User-Agent":_decode(h.User_Agent),"Content-Type":_decode(getattr(h,"Content_Type",b"")),"Content-Length":_decode(getattr(h,"Content_Length",b""))}})
        elif HTTPResponse in pkt:
            h=pkt[HTTPResponse]; protocol="HTTP"; code=_decode(h.Status_Code); reason=_decode(h.Reason_Phrase); info=f"HTTP {code} {reason}"; layers.append({"name":"Hypertext Transfer Protocol","fields":{"Status":f"{code} {reason}","Status Code":code,"Server":_decode(h.Server),"Content-Type":_decode(getattr(h,"Content_Type",b"")),"Content-Length":_decode(getattr(h,"Content_Length",b""))}})
    except Exception: pass
    return {"id":str(uuid.uuid4()),"number":number,"timestamp":ts,"time_str":datetime.fromtimestamp(ts,tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3],"src_ip":src_ip,"dst_ip":dst_ip,"src_port":src_port,"dst_port":dst_port,"protocol":protocol,"length":len(raw),"payload_size":payload_size,"info":info or pkt.summary(),"layers":layers,"hex":raw.hex(),"flags":_tcp_flags(int(pkt[TCP].flags)) if TCP in pkt else ""}

@dataclass
class ThreatState:
    syn_counts:Dict[str,Deque[float]]=field(default_factory=lambda:defaultdict(lambda:deque(maxlen=200)))
    port_scan:Dict[str,set]=field(default_factory=lambda:defaultdict(set)); icmp_counts:Dict[str,Deque[float]]=field(default_factory=lambda:defaultdict(lambda:deque(maxlen=200)))

def detect_threats(p,state):
    now=p["timestamp"]; src=p.get("src_ip"); dst=p.get("dst_ip"); port=p.get("dst_port"); flags=p.get("flags","")
    if "SYN" in flags and "ACK" not in flags and src:
        q=state.syn_counts[src]; q.append(now)
        while q and now-q[0]>5:q.popleft()
        if len(q)>60:return {"id":str(uuid.uuid4()),"severity":"critical","type":"SYN Flood","title":f"Possible SYN flood from {src}","description":f"{len(q)} SYN packets in last 5s","src":src,"dst":dst,"timestamp":now,"packet_id":p["id"]}
    if p.get("protocol") in ("TCP","HTTP","HTTPS","TLS","SSH","FTP") and src and dst and port:
        k=f"{src}->{dst}"; state.port_scan[k].add(port)
        if len(state.port_scan[k])>15:
            n=len(state.port_scan[k]); state.port_scan[k]=set(); return {"id":str(uuid.uuid4()),"severity":"high","type":"Port Scan","title":f"Port scan: {src} → {dst}","description":f"Probed {n} ports on {dst}","src":src,"dst":dst,"timestamp":now,"packet_id":p["id"]}
    if p.get("protocol")=="HTTP" and "POST" in p.get("info","") and any(x in p.get("info","").lower() for x in ("login","auth","signin","password")):
        return {"id":str(uuid.uuid4()),"severity":"medium","type":"Cleartext Credentials","title":"Unencrypted authentication request","description":"HTTP authentication request observed without TLS","src":src,"dst":dst,"timestamp":now,"packet_id":p["id"]}
    return None

LOCAL_HOSTS=[("192.168.1.10","AA:BB:CC:11:22:33"),("192.168.1.42","AA:BB:CC:11:22:34"),("192.168.1.105","AA:BB:CC:11:22:35")]; GATEWAY=("192.168.1.1","AA:BB:CC:00:00:01"); EXTERNAL=[("142.250.80.46","google.com"),("185.199.108.153","github.com"),("8.8.8.8","dns.google")]
def _simulate_one(anomaly=False):
    local=random.choice(LOCAL_HOSTS); ip,host=random.choice(EXTERNAL)
    if anomaly:return Ether(src=local[1],dst=GATEWAY[1])/IP(src=local[0],dst=ip)/TCP(sport=random.randint(40000,65000),dport=random.choice([80,443,22]),flags="S")
    r=random.random()
    if r<.65:return Ether(src=local[1],dst=GATEWAY[1])/IP(src=local[0],dst=ip)/TCP(sport=random.randint(40000,65000),dport=random.choice([80,443,22]),flags=random.choice(["S","SA","A","PA","FA"]))
    if r<.85:
        from scapy.layers.dns import DNSQR
        return Ether(src=local[1],dst=GATEWAY[1])/IP(src=local[0],dst="8.8.8.8")/UDP(sport=random.randint(40000,65000),dport=53)/DNS(rd=1,qd=DNSQR(qname=host))
    return Ether(src=local[1],dst=GATEWAY[1])/IP(src=local[0],dst=ip)/ICMP(type=8)

class CaptureSession:
    MIN_PACKET_LIMIT=1000; MAX_PACKET_LIMIT=1000000; DEFAULT_PACKET_LIMIT=5000; MAX_THREATS=300
    def __init__(self):
        self.packet_limit=self.DEFAULT_PACKET_LIMIT; self.packets=deque(maxlen=self.packet_limit); self.threats=deque(maxlen=self.MAX_THREATS); self.by_id={}; self.running=False; self.mode="idle"; self.interface=""; self.counter=0; self.start_ts=None; self.dropped_packets=0; self.threat_state=ThreatState(); self.flows={}; self.hosts={}; self.timeline=deque(maxlen=120); self._task=None; self._subscribers=[]; self._reset_capture_metadata()
    def _reset_capture_metadata(self):
        self.capture_id=str(uuid.uuid4()); self.capture_created_at=time.time(); self.requested_mode="idle"; self.last_packet_at=None; self.capture_error=None; self.fallback_active=False; self.switch_count=0; self.interface_history=deque(maxlen=50)
    def configure_packet_limit(self,packet_limit:int):
        if isinstance(packet_limit,bool) or not isinstance(packet_limit,int) or not self.MIN_PACKET_LIMIT<=packet_limit<=self.MAX_PACKET_LIMIT:
            raise ValueError(f"packet_limit must be between {self.MIN_PACKET_LIMIT} and {self.MAX_PACKET_LIMIT}")
        if packet_limit==self.packet_limit:return
        retained=list(self.packets)[-packet_limit:]; removed=max(0,len(self.packets)-len(retained)); self.dropped_packets+=removed
        self.packet_limit=packet_limit; self.packets=deque(retained,maxlen=packet_limit); retained_ids={packet["id"] for packet in retained}; self.by_id={pid:packet for pid,packet in self.by_id.items() if pid in retained_ids}
    async def start(self,interface="simulated",reset_started_at=True):
        if self.running:return
        now=time.time(); previous=self.interface; requested_mode="live" if interface not in ("simulated","",None) else "simulated"
        self.running=True; self.interface=interface; self.start_ts=now if reset_started_at or self.start_ts is None else self.start_ts; self.mode=requested_mode; self.requested_mode=requested_mode; self.capture_error=None; self.fallback_active=False
        if previous and previous!=interface:self.switch_count+=1
        self.interface_history.append({"from":previous or None,"to":interface,"timestamp":now,"preserved_packets":len(self.packets),"reason":"switch" if previous and previous!=interface else "start" if not previous else "resume"})
        self._task=asyncio.create_task(self._loop())
    async def stop(self):
        self.running=False
        if self._task:
            self._task.cancel()
            try:await self._task
            except BaseException:pass
            self._task=None
        self.mode="idle"
    def clear(self):
        self.packets.clear(); self.threats.clear(); self.by_id.clear(); self.flows.clear(); self.hosts.clear(); self.timeline.clear(); self.counter=0; self.start_ts=None; self.dropped_packets=0; self.threat_state=ThreatState(); self.interface=""; self.mode="idle"; self._reset_capture_metadata()
    async def switch_interface(self,interface,preserve_packets=True,packet_limit=None):
        if not isinstance(interface,str) or not interface.strip():raise ValueError("interface is required")
        interface=interface.strip(); previous=self.interface; retained=len(self.packets)
        if packet_limit is not None:self.configure_packet_limit(packet_limit)
        if self.running and interface==previous:return {"status":"unchanged","previous_interface":previous,"preserved_packets":len(self.packets),"stats":self.stats()}
        await self.stop()
        if not preserve_packets:self.clear(); retained=0
        await self.start(interface,reset_started_at=not preserve_packets)
        return {"status":"switched","previous_interface":previous,"preserved_packets":min(retained,len(self.packets)),"stats":self.stats()}
    def subscribe(self):q=asyncio.Queue(maxsize=1000); self._subscribers.append(q); return q
    def unsubscribe(self,q):
        if q in self._subscribers:self._subscribers.remove(q)
    async def _broadcast(self,msg):
        for q in list(self._subscribers):
            try:q.put_nowait(msg)
            except asyncio.QueueFull:self.unsubscribe(q)
    def ingest(self,pkt,ts=None):
        self.counter+=1; ts=ts if ts is not None else time.time(); p=dissect_packet(pkt,self.counter,ts); evicted_id=self.packets[0]["id"] if len(self.packets)==self.packet_limit else None; self.packets.append(p); self.by_id[p["id"]]=p
        if evicted_id is not None:self.by_id.pop(evicted_id,None); self.dropped_packets+=1
        self.last_packet_at=ts
        if p["src_ip"] and p["dst_ip"]:
            key=tuple(sorted((p["src_ip"],p["dst_ip"]))); f=self.flows.setdefault(key,{"a":key[0],"b":key[1],"packets":0,"bytes":0,"protocols":set(),"last_ts":ts}); f["packets"]+=1; f["bytes"]+=p["length"]; f["protocols"].add(p["protocol"]); f["last_ts"]=ts
            for ip in (p["src_ip"],p["dst_ip"]):
                h=self.hosts.setdefault(ip,{"ip":ip,"packets":0,"bytes":0,"ports":set(),"last_ts":ts}); h["packets"]+=1; h["bytes"]+=p["length"]; h["last_ts"]=ts
                if p.get("dst_port"):h["ports"].add(p["dst_port"])
        bt=int(ts)
        if not self.timeline or self.timeline[-1]["t"]!=bt:self.timeline.append({"t":bt,"pps":0,"bps":0,"by_proto":{}})
        b=self.timeline[-1]; b["pps"]+=1; b["bps"]+=p["length"]*8; b["by_proto"][p["protocol"]]=b["by_proto"].get(p["protocol"],0)+1
        t=detect_threats(p,self.threat_state)
        if t:self.threats.append(t)
        return p
    async def _loop(self):
        try:
            if self.mode=="live":
                try:
                    from scapy.all import AsyncSniffer
                    loop=asyncio.get_running_loop()
                    def cb(pkt):
                        p=self.ingest(pkt); asyncio.run_coroutine_threadsafe(self._broadcast({"type":"packet","data":p}),loop)
                    sniffer=AsyncSniffer(iface=self.interface,prn=cb,store=False); sniffer.start()
                    try:
                        while self.running:await asyncio.sleep(.5)
                    finally:sniffer.stop()
                    return
                except Exception as exc:
                    if not self.running:return
                    self.capture_error=f"Live capture unavailable ({type(exc).__name__})"; self.fallback_active=True; self.mode="simulated"
            while self.running:
                p=self.ingest(_simulate_one(random.random()<.01)); await self._broadcast({"type":"packet","data":p}); await asyncio.sleep(.05)
        except asyncio.CancelledError:pass
    def ingest_pcap_bytes(self,data):
        n=0
        for pkt in rdpcap(io.BytesIO(data)):
            self.ingest(pkt,float(pkt.time) if getattr(pkt,"time",None) else time.time()); n+=1
        self.mode="pcap"; return n
    def stats(self):
        now=time.time(); total=len(self.packets); total_bytes=sum(p["length"] for p in self.packets); duration=max(1,now-(self.start_ts or now)); pc={}
        for p in self.packets:pc[p["protocol"]]=pc.get(p["protocol"],0)+1
        return {"running":self.running,"mode":self.mode,"requested_mode":self.requested_mode,"interface":self.interface,"capture_id":self.capture_id,"capture_created_at":self.capture_created_at,"capture_started_at":self.start_ts,"last_packet_at":self.last_packet_at,"switch_count":self.switch_count,"total_packets":total,"total_bytes":total_bytes,"packet_limit":self.packet_limit,"buffer_utilization":round(total/self.packet_limit,4),"dropped_packets":self.dropped_packets,"capture_health":self.capture_health(now),"pps":round(total/duration,1),"mbps":round(total_bytes*8/duration/1e6,3),"threats":len(self.threats),"unique_hosts":len(self.hosts),"unique_flows":len(self.flows),"protocol_counts":pc,"duration_sec":round(duration,1)}
    def capture_health(self,now=None):
        now=now or time.time()
        if not self.running:
            if self.mode in ("pcap","replay"):return {"state":"ready","reason":"Offline capture evidence is loaded.","fallback_active":False}
            return {"state":"idle","reason":"Capture is stopped.","fallback_active":self.fallback_active}
        if self.fallback_active:return {"state":"degraded","reason":"Live capture failed; simulated fallback is active.","fallback_active":True}
        if self.capture_error:return {"state":"error","reason":self.capture_error,"fallback_active":False}
        if self.running and self.last_packet_at is None and self.start_ts and now-self.start_ts>5:return {"state":"warning","reason":"Capture is running but no packets have arrived yet.","fallback_active":False}
        if self.running and self.last_packet_at and now-self.last_packet_at>10:return {"state":"warning","reason":"No packets observed in the last 10 seconds.","fallback_active":False}
        if self.dropped_packets and len(self.packets)>=self.packet_limit:return {"state":"warning","reason":"The retention limit is active; oldest packets are being evicted.","fallback_active":False}
        return {"state":"healthy","reason":"Capture is running and packet processing is responsive.","fallback_active":False}
    def diagnostics(self):
        stats=self.stats()
        return {"capture_id":self.capture_id,"created_at":self.capture_created_at,"started_at":self.start_ts,"running":self.running,"requested_mode":self.requested_mode,"actual_mode":self.mode,"interface":self.interface,"health":stats["capture_health"],"last_packet_at":self.last_packet_at,"buffer":{"packets":len(self.packets),"limit":self.packet_limit,"utilization":stats["buffer_utilization"],"evicted_packets":self.dropped_packets},"switch_count":self.switch_count,"interface_history":list(self.interface_history),"task_active":bool(self._task and not self._task.done())}
    def timeline_series(self):return list(self.timeline)
    def top_talkers(self,limit=10):return [{"ip":h["ip"],"packets":h["packets"],"bytes":h["bytes"],"ports":sorted(h["ports"])[:10]} for h in sorted(self.hosts.values(),key=lambda x:x["bytes"],reverse=True)[:limit]]
    def topology(self):return {"nodes":[{"id":ip,"packets":h["packets"],"bytes":h["bytes"],"ports":sorted(h["ports"])[:8],"type":"local" if ip.startswith(("10.","192.168.","172.")) else "external"} for ip,h in self.hosts.items()],"edges":[{"source":a,"target":b,"packets":f["packets"],"bytes":f["bytes"],"protocols":sorted(f["protocols"])[:4]} for (a,b),f in self.flows.items()]}
    def list_packets(self,limit=500,protocol=None,q=None):
        out=[]; proto=(protocol or "").upper(); qs=(q or "").lower()
        for p in reversed(self.packets):
            if proto and p["protocol"].upper()!=proto:continue
            if qs and qs not in f"{p['src_ip']} {p['dst_ip']} {p['protocol']} {p['info']} {p.get('src_port','')} {p.get('dst_port','')}".lower():continue
            out.append({k:v for k,v in p.items() if k not in ("layers","hex")})
            if len(out)>=limit:break
        return out
    def list_threats(self):return list(reversed(self.threats))
    def get_packet(self,pid):return self.by_id.get(pid)
