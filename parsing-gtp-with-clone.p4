#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/defines.p4"

typedef bit<9>  egress_spec_t; 

struct headers {
    ethernet_t        ethernet;
    vlan_tag_t        vlan;

    ipv4_t            ipv4;
    udp_t             udp;

    sctp_t            sctp;
    sctp_chunk_t      sctp_chunk;

    gtp_v1_t             gtp;

    ipv4_t inner_ipv4;
    udp_t inner_udp;

    tcp_t tcp;
    icmp_t icmp;

}

struct metadata {
    bit<9> out_port;
    bit<32> pkt_len;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x8100: parse_vlan;
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            132: parse_sctp;
            default: accept;
        }
    }

    state parse_sctp {
        packet.extract(hdr.sctp);
        transition parse_sctp_chunk;
    }

    state parse_sctp_chunk {
        packet.extract(hdr.sctp_chunk);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            UDP_PORT_GTP: parse_gtp;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            1:   parse_icmp;
            6:   parse_tcp;
            17:  parse_inner_udp;
            132: parse_sctp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition parse_inner_ipv4;
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action clone_packet() {
        const bit<32> REPORT_MIRROR_SESSION_ID = 500;
        // Clone from ingress to egress pipeline
        clone(CloneType.I2E, REPORT_MIRROR_SESSION_ID);
    }

    table clone_all {
        actions = { clone_packet; }
        size = 1;
        default_action = clone_packet();
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send(egress_spec_t port) {
        standard_metadata.egress_spec = port;
    }

    apply {
        if (!hdr.ethernet.isValid()) {
            drop();
            return;
        }

        clone_all.apply();
        // Forward: 0->1, 1->0, others drop
        if (standard_metadata.ingress_port == 0) {
            send(1);
        } else if (standard_metadata.ingress_port == 1) {
            send(0);
        } else {
            drop();
        }
    }

}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // Solo clonados
        if (standard_metadata.instance_type  == 1) {
            // Invalida cabeceras exteriores (outer stack)
            hdr.ipv4.setInvalid();       // outer IPv4
            hdr.udp.setInvalid();        // outer UDP (2152)
            hdr.gtp.setInvalid();
            standard_metadata.egress_spec = 2;
        }


    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);

        // solo clonados
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);

        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.sctp);
        packet.emit(hdr.sctp_chunk);
    }
}


control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.inner_ipv4.isValid(),
            {
                hdr.inner_ipv4.version,
                hdr.inner_ipv4.ihl,
                hdr.inner_ipv4.diffserv,
                hdr.inner_ipv4.totalLen,
                hdr.inner_ipv4.identification,
                hdr.inner_ipv4.flags,
                hdr.inner_ipv4.fragOffset,
                hdr.inner_ipv4.ttl,
                hdr.inner_ipv4.protocol,
                hdr.inner_ipv4.srcAddr,
                hdr.inner_ipv4.dstAddr
            },
            hdr.inner_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
