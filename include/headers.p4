// ---------- L2 / VLAN ----------
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> etherType;
}

// ---------- L3/L4 ----------
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header features_t {
    bit<16> magic;
    bit<32> pkt_len;
    bit<48> eth_src;
    bit<48> eth_dst;
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<8>  ip_ttl;
    bit<8>  ip_proto;
    bit<16> src_port;
    bit<16> dst_port;
    bit<1>  tcp_syn;
    bit<1>  tcp_ack;
    bit<1>  tcp_rst;
    bit<5>  padding;
}

header sctp_t {
    bit<16> srcPort;      // Source port
    bit<16> dstPort;      // Destination port
    bit<32> verificationTag; // Verification Tag
    bit<32> checksum;     // Adler-32 (o CRC32C)
}

header sctp_chunk_t {
    bit<8>  type;          // Chunk Type
    bit<8>  flags;         // Chunk Flags (dependen del tipo)
    bit<16> length;        // Total length of this chunk (including header)
}


// ---------- GTP-U base ----------
header gtp_v1_t {
    bit<3>        version;               /** For GTPv1, this has a value of 1. */
    bit           protocol_type;         /** GTP (value 1) from GTP' (value 0) */
    bit           reserved;
    bit           extension_header_flag; /** extension header optional field. */
    bit           seq_number_flag;       /** Sequence Number optional field */
    bit           n_pdu_number_flag;     /** N-PDU number optional field */
    bit<8>        message_type;          /** types of messages are defined in 3GPP TS 29.060 section 7.1 */
    bit<16>       message_length;        /** length of the payload in bytes */
    bit<32>       teid;                  /** Tunnel endpoint identifier */
    bit<16>       sequence_number;       /** optional */
    bit<8>        n_pdu_number;          /** optional */
    bit<40>        next_extension_hdr_type; /** optional if any of the E, S, or PN bits are on. The field must be interpreted only if the E bit is on */
}
