from etherlens.topology import MAX_EDGE_CONNECTIONS, build_topology


def _host(ip, **values):
    row = {"ip": ip, "is_local": ip.startswith("10."), "total_packets": 5, "total_bytes": 500,
           "protocols": ["TLS"], "services": [], "connections": [], "domains": [],
           "risk": {"score": 0, "level": "none"}, "finding_count": 0}
    row.update(values)
    return row


def _connection(a_port=50000, b_port=443, size=1000):
    return {"a_ip": "10.0.0.2", "a_port": a_port, "b_ip": "203.0.113.5", "b_port": b_port,
            "packets": 4, "bytes": size, "protocols": ["TLS"], "state": "established",
            "first_seen": 10, "last_seen": 12, "duration_ms": 2000, "retransmissions": 1,
            "duplicate_acks": 0, "out_of_order": 0, "zero_windows": 0, "resets": 0}


def test_topology_nodes_expose_searchable_analyst_and_host_metadata():
    result = build_topology([
        _host("10.0.0.2", alias="Workstation", watchlisted=True, mac="aa:bb:cc:dd:ee:ff",
              hostname="desk.example", activity_state="active", services=[{"port": 22, "protocol": "SSH"}],
              connections=[{"ports": [443]}], domains=[{"domain": "api.example"}],
              risk={"score": 25, "level": "medium"}, finding_count=2),
        _host("203.0.113.5"),
    ], [_connection()])
    node = next(row for row in result["nodes"] if row["id"] == "10.0.0.2")
    assert node["alias"] == "Workstation"
    assert node["watchlisted"] is True
    assert node["ports"] == [22, 443]
    assert node["domains"] == ["api.example"]
    assert result["summary"] == {"hosts": 2, "connections": 1, "host_pairs": 1,
                                 "watchlisted_hosts": 1, "flagged_hosts": 1}


def test_topology_aggregates_ip_pair_but_preserves_flow_drill_down():
    result = build_topology([_host("10.0.0.2"), _host("203.0.113.5")],
                            [_connection(50000, 443, 1000), _connection(50001, 8443, 2000)])
    edge = result["edges"][0]
    assert edge["packets"] == 8
    assert edge["bytes"] == 3000
    assert edge["connection_count"] == 2
    assert [row["a_port"] for row in edge["connections"]] == [50001, 50000]
    assert edge["tcp_health"]["retransmissions"] == 2
    assert "source_port" not in edge


def test_single_connection_edge_exposes_compatible_port_hint():
    edge = build_topology([_host("10.0.0.2"), _host("203.0.113.5")], [_connection()])["edges"][0]
    assert edge["source"] == "10.0.0.2"
    assert edge["source_port"] == 50000
    assert edge["target_port"] == 443


def test_edge_flow_details_are_bounded():
    connections = [_connection(40000 + index, 443, index + 1) for index in range(MAX_EDGE_CONNECTIONS + 10)]
    edge = build_topology([_host("10.0.0.2"), _host("203.0.113.5")], connections)["edges"][0]
    assert edge["connection_count"] == MAX_EDGE_CONNECTIONS + 10
    assert edge["connections_truncated"] is True
    assert len(edge["connections"]) == MAX_EDGE_CONNECTIONS
    assert edge["connections"][0]["a_port"] == 40000 + MAX_EDGE_CONNECTIONS + 9
