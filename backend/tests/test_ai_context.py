from etherlens.ai_context import connection_context, connection_prompt


def connection():
    return {"a_ip":"10.0.0.2","a_port":51000,"b_ip":"1.1.1.1","b_port":443,"packets":3,"state":"established","protocols":["TCP","TLS"]}


def packets():
    return [
        {"id":"p1","src_ip":"10.0.0.2","src_port":51000,"dst_ip":"1.1.1.1","dst_port":443,"protocol":"TCP"},
        {"id":"p2","src_ip":"1.1.1.1","src_port":443,"dst_ip":"10.0.0.2","dst_port":51000,"protocol":"TLS"},
        {"id":"other","src_ip":"10.0.0.2","src_port":52000,"dst_ip":"1.1.1.1","dst_port":443,"protocol":"TCP"},
    ]


def test_connection_context_is_exact_and_evidence_bounded():
    ctx=connection_context(
        connection(),packets(),
        {"events":[{"src_ip":"10.0.0.2","dst_ip":"8.8.8.8","query":"example.com"}]},
        {"events":[]},
        {"events":[{"src_ip":"10.0.0.2","dst_ip":"1.1.1.1","sni":"example.com"}]},
        {"p1":{"events":[],"healthy":True},"other":{"events":["reset"],"healthy":False}},
        [{"src":"10.0.0.2","dst":"1.1.1.1","type":"review"}],
    )
    assert [p["id"] for p in ctx["packets"]]==["p1","p2"]
    assert set(ctx["tcp_health"])=={"p1"}
    assert len(ctx["tls"]["events"])==1
    assert len(ctx["security_findings"])==1
    assert "not decrypted or inferred" in ctx["tls"]["visibility"]


def test_connection_prompt_is_bounded_and_has_encryption_boundary():
    ctx=connection_context(connection(),packets()*100,{"events":[]},{"events":[]},{"events":[]},{})
    prompt=connection_prompt(ctx,3000)
    assert len(prompt)<=3000
    assert "Never claim to decrypt" in prompt
    assert "uncertainty" in prompt


def test_reverse_direction_packet_matches_exact_tuple():
    ctx=connection_context(connection(),[packets()[1]],{"events":[]},{"events":[]},{"events":[]},{})
    assert len(ctx["packets"])==1
