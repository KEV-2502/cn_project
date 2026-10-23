from typing import Optional, Dict, Set, List
from collections import defaultdict
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.pcap import PcapFile
from backend.app.models.flow import NetworkFlow
from backend.app.models.alert import ThreatAlert
from backend.app.schemas.topology import (
    TopologyResponse,
    TopologyNode,
    TopologyEdge,
    TopologySummary,
    TopologyAlertSummary,
)

router = APIRouter(prefix="/topology", tags=["Network Topology"])

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _max_severity(severities: List[str]) -> Optional[str]:
    """Return the highest severity from a list of severity strings."""
    if not severities:
        return None
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s.upper(), 0))


@router.get("", response_model=TopologyResponse)
def get_network_topology(
    pcap_id: Optional[int] = Query(None, description="Filter topology by specific PCAP ID"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (TCP, UDP, ICMP, DNS)"),
    min_flows: int = Query(1, ge=1, description="Minimum flow count per communication edge"),
    only_alerts: bool = Query(False, description="Filter to show only hosts associated with alerts"),
    limit_nodes: int = Query(100, ge=5, le=500, description="Maximum number of nodes to return for performance"),
    db: Session = Depends(get_db),
):
    """Generates an aggregated network topology graph from observed flows and alerts."""
    pcap_name: Optional[str] = None
    if pcap_id is not None:
        pcap_record = db.query(PcapFile).filter(PcapFile.id == pcap_id).first()
        if not pcap_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PCAP capture with ID {pcap_id} not found",
            )
        pcap_name = pcap_record.filename

    # 1. Fetch flows with optional filters
    flow_query = db.query(NetworkFlow)
    if pcap_id is not None:
        flow_query = flow_query.filter(NetworkFlow.pcap_id == pcap_id)
    if protocol:
        flow_query = flow_query.filter(NetworkFlow.protocol == protocol.upper())

    flows = flow_query.all()

    # 2. Fetch alerts
    alert_query = db.query(ThreatAlert)
    if pcap_id is not None:
        alert_query = alert_query.filter(ThreatAlert.pcap_id == pcap_id)
    alerts = alert_query.all()

    # 3. Index alerts by IP and by directed/undirected host pairs
    node_alerts: Dict[str, List[TopologyAlertSummary]] = defaultdict(list)
    edge_alerts: Dict[tuple, List[TopologyAlertSummary]] = defaultdict(list)

    for a in alerts:
        summary = TopologyAlertSummary(
            id=a.id,
            rule_id=a.rule_id,
            rule_name=a.rule_name,
            severity=a.severity,
            risk_score=float(a.risk_score),
            description=a.description,
            timestamp=float(a.timestamp),
        )
        if a.src_ip:
            node_alerts[a.src_ip].append(summary)
        if a.dst_ip:
            node_alerts[a.dst_ip].append(summary)
        if a.src_ip and a.dst_ip:
            edge_alerts[(a.src_ip, a.dst_ip)].append(summary)
            edge_alerts[(a.dst_ip, a.src_ip)].append(summary)

    # 4. Aggregate flows into directed communication edges
    raw_edges: Dict[tuple, Dict] = defaultdict(lambda: {
        "flow_count": 0,
        "total_packets": 0,
        "total_bytes": 0,
        "forward_packets": 0,
        "backward_packets": 0,
        "forward_bytes": 0,
        "backward_bytes": 0,
        "protocols": set(),
        "ports": set(),
        "tcp_states": set(),
    })

    for f in flows:
        pair_key = (f.src_ip, f.dst_ip)
        e = raw_edges[pair_key]
        e["flow_count"] += 1
        e["total_packets"] += f.total_packets
        e["total_bytes"] += f.total_bytes
        e["forward_packets"] += f.forward_packets
        e["backward_packets"] += f.backward_packets
        e["forward_bytes"] += f.forward_bytes
        e["backward_bytes"] += f.backward_bytes
        e["protocols"].add(f.protocol)
        if f.dst_port is not None:
            e["ports"].add(f.dst_port)
        if f.tcp_state and f.tcp_state != "N/A":
            e["tcp_states"].add(f.tcp_state)

    # Filter edges by min_flows
    filtered_edges = {
        k: v for k, v in raw_edges.items() if v["flow_count"] >= min_flows
    }

    # 5. Aggregate hosts into nodes
    raw_nodes: Dict[str, Dict] = defaultdict(lambda: {
        "total_flows": 0,
        "outgoing_flows": 0,
        "incoming_flows": 0,
        "sent_packets": 0,
        "received_packets": 0,
        "sent_bytes": 0,
        "received_bytes": 0,
        "protocols": set(),
        "peers": set(),
    })

    for (src, dst), e in filtered_edges.items():
        # Source host metrics
        s_node = raw_nodes[src]
        s_node["total_flows"] += e["flow_count"]
        s_node["outgoing_flows"] += e["flow_count"]
        s_node["sent_packets"] += e["forward_packets"]
        s_node["received_packets"] += e["backward_packets"]
        s_node["sent_bytes"] += e["forward_bytes"]
        s_node["received_bytes"] += e["backward_bytes"]
        s_node["protocols"].update(e["protocols"])
        s_node["peers"].add(dst)

        # Destination host metrics
        d_node = raw_nodes[dst]
        d_node["total_flows"] += e["flow_count"]
        d_node["incoming_flows"] += e["flow_count"]
        d_node["sent_packets"] += e["backward_packets"]
        d_node["received_packets"] += e["forward_packets"]
        d_node["sent_bytes"] += e["backward_bytes"]
        d_node["received_bytes"] += e["forward_bytes"]
        d_node["protocols"].update(e["protocols"])
        d_node["peers"].add(src)

    # 6. Apply only_alerts filter if requested
    if only_alerts:
        filtered_nodes_map = {
            ip: data for ip, data in raw_nodes.items() if len(node_alerts.get(ip, [])) > 0
        }
    else:
        filtered_nodes_map = dict(raw_nodes)

    total_unfiltered_nodes = len(filtered_nodes_map)
    is_truncated = False

    # 7. Apply limit_nodes if node count exceeds limit
    if len(filtered_nodes_map) > limit_nodes:
        is_truncated = True

        def node_sort_key(item):
            ip, d = item
            alerts_for_ip = node_alerts.get(ip, [])
            max_sev = _max_severity([a.severity for a in alerts_for_ip])
            sev_score = SEVERITY_ORDER.get(max_sev, 0) if max_sev else 0
            tot_bytes = d["sent_bytes"] + d["received_bytes"]
            return (sev_score, tot_bytes, d["total_flows"])

        sorted_items = sorted(filtered_nodes_map.items(), key=node_sort_key, reverse=True)
        filtered_nodes_map = dict(sorted_items[:limit_nodes])

    active_ips = set(filtered_nodes_map.keys())

    # 8. Format final Node models
    output_nodes: List[TopologyNode] = []
    for ip, d in filtered_nodes_map.items():
        tot_bytes = d["sent_bytes"] + d["received_bytes"]
        tot_pkts = d["sent_packets"] + d["received_packets"]
        ip_alerts = node_alerts.get(ip, [])
        max_sev = _max_severity([a.severity for a in ip_alerts])

        # Infer host communication role
        if d["total_flows"] > 0:
            if d["outgoing_flows"] >= 0.8 * d["total_flows"]:
                role = "client"
            elif d["incoming_flows"] >= 0.8 * d["total_flows"]:
                role = "server"
            else:
                role = "mixed"
        else:
            role = "mixed"

        node_obj = TopologyNode(
            id=ip,
            ip=ip,
            total_flows=d["total_flows"],
            total_packets=tot_pkts,
            total_bytes=tot_bytes,
            sent_packets=d["sent_packets"],
            received_packets=d["received_packets"],
            sent_bytes=d["sent_bytes"],
            received_bytes=d["received_bytes"],
            protocols=sorted(list(d["protocols"])),
            peer_count=len(d["peers"]),
            peers=sorted(list(d["peers"])),
            alert_count=len(ip_alerts),
            max_severity=max_sev,
            alerts=ip_alerts,
            role=role,
        )
        output_nodes.append(node_obj)

    # 9. Format final Edge models (both endpoints must exist in active_ips)
    output_edges: List[TopologyEdge] = []
    for (src, dst), e in filtered_edges.items():
        if src in active_ips and dst in active_ips:
            e_alerts = edge_alerts.get((src, dst), [])
            # Deduplicate alert summaries by ID
            seen_ids = set()
            unique_e_alerts = []
            for al in e_alerts:
                if al.id not in seen_ids:
                    seen_ids.add(al.id)
                    unique_e_alerts.append(al)

            max_sev = _max_severity([a.severity for a in unique_e_alerts])
            edge_obj = TopologyEdge(
                id=f"{src}->{dst}",
                source=src,
                target=dst,
                flow_count=e["flow_count"],
                total_packets=e["total_packets"],
                total_bytes=e["total_bytes"],
                forward_packets=e["forward_packets"],
                backward_packets=e["backward_packets"],
                forward_bytes=e["forward_bytes"],
                backward_bytes=e["backward_bytes"],
                protocols=sorted(list(e["protocols"])),
                ports=sorted(list(e["ports"]))[:15],  # top 15 target ports
                tcp_states=sorted(list(e["tcp_states"])),
                has_alerts=len(unique_e_alerts) > 0,
                alert_count=len(unique_e_alerts),
                max_severity=max_sev,
                alerts=unique_e_alerts,
            )
            output_edges.append(edge_obj)

    # 10. Summary metrics
    alerted_nodes_cnt = sum(1 for n in output_nodes if n.alert_count > 0)
    alerted_edges_cnt = sum(1 for e in output_edges if e.has_alerts)
    summary_flows = sum(e.flow_count for e in output_edges)
    summary_pkts = sum(e.total_packets for e in output_edges)
    summary_bytes = sum(e.total_bytes for e in output_edges)

    summary = TopologySummary(
        total_nodes=len(output_nodes),
        total_edges=len(output_edges),
        total_flows=summary_flows,
        total_packets=summary_pkts,
        total_bytes=summary_bytes,
        alerted_nodes_count=alerted_nodes_cnt,
        alerted_edges_count=alerted_edges_cnt,
        is_truncated=is_truncated,
        total_unfiltered_nodes=total_unfiltered_nodes,
        pcap_id=pcap_id,
        pcap_name=pcap_name,
    )

    return TopologyResponse(
        nodes=output_nodes,
        edges=output_edges,
        summary=summary,
    )
