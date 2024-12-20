CREATE TABLE IF NOT EXISTS flows
(
    type Int32,
    time_received UInt64,
    sequence_num UInt32,
    sampling_rate UInt64,
    flow_direction UInt32,

    sampler_address String,

    time_flow_start UInt64,
    time_flow_end UInt64,

    bytes UInt64,
    packets UInt64,

    src_addr String,
    dst_addr String,

    etype UInt32,

    proto UInt32,

    src_port UInt32,
    dst_port UInt32,

    forwarding_status UInt32,
    tcp_flags UInt32,
    icmp_type UInt32,
    icmp_code UInt32,

    fragment_id UInt32,
    fragment_offset UInt32
) ENGINE = Null();

CREATE TABLE IF NOT EXISTS networks (
    network String,
    enable_ban Bool DEFAULT false,
    ban_for_pps Bool DEFAULT false,
    ban_for_bandwidth Bool DEFAULT false,
    ban_for_flows Bool DEFAULT false,
    ban_for_tcp_bandwidth Bool DEFAULT false,
    ban_for_udp_bandwidth Bool DEFAULT false,
    ban_for_icmp_bandwidth Bool DEFAULT false,
    ban_for_tcp_syn_bandwidth Bool DEFAULT false,
    ban_for_ip_fragments_bandwidth Bool DEFAULT false,
    ban_for_tcp_pps Bool DEFAULT false,
    ban_for_udp_pps Bool DEFAULT false,
    ban_for_icmp_pps Bool DEFAULT false,
    ban_for_tcp_syn_pps Bool DEFAULT false,
    ban_for_ip_fragments_pps Bool DEFAULT false,
    threshold_pps UInt64 DEFAULT 0,
    threshold_mbps UInt64 DEFAULT 0,
    threshold_flows UInt64 DEFAULT 0,
    threshold_tcp_mbps UInt64 DEFAULT 0,
    threshold_udp_mbps UInt64 DEFAULT 0,
    threshold_icmp_mbps UInt64 DEFAULT 0,
    threshold_tcp_syn_mbps UInt64 DEFAULT 0,
    threshold_ip_fragments_mbps UInt64 DEFAULT 0,
    threshold_tcp_pps UInt64 DEFAULT 0,
    threshold_udp_pps UInt64 DEFAULT 0,
    threshold_icmp_pps UInt64 DEFAULT 0,
    threshold_tcp_syn_pps UInt64 DEFAULT 0,
    threshold_ip_fragments_pps UInt64 DEFAULT 0,
    tags Array(String) DEFAULT []
)
ENGINE = MergeTree()
PRIMARY KEY network;

CREATE DICTIONARY IF NOT EXISTS dict_networks (
    network String,
    enable_ban Bool,
    ban_for_pps Bool,
    ban_for_bandwidth Bool,
    ban_for_flows Bool,
    ban_for_tcp_bandwidth Bool,
    ban_for_udp_bandwidth Bool,
    ban_for_icmp_bandwidth Bool,
    ban_for_tcp_syn_bandwidth Bool,
    ban_for_ip_fragments_bandwidth Bool,
    ban_for_tcp_pps Bool,
    ban_for_udp_pps Bool,
    ban_for_icmp_pps Bool,
    ban_for_tcp_syn_pps Bool,
    ban_for_ip_fragments_pps Bool,
    threshold_pps UInt64,
    threshold_mbps UInt64,
    threshold_flows UInt64,
    threshold_tcp_mbps UInt64,
    threshold_udp_mbps UInt64,
    threshold_icmp_mbps UInt64,
    threshold_tcp_syn_mbps UInt64,
    threshold_ip_fragments_mbps UInt64,
    threshold_tcp_pps UInt64,
    threshold_udp_pps UInt64,
    threshold_icmp_pps UInt64,
    threshold_tcp_syn_pps UInt64,
    threshold_ip_fragments_pps UInt64,
    tags Array(String)
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(TABLE 'networks'))
LAYOUT(HASHED())
LIFETIME(3600);

CREATE DICTIONARY IF NOT EXISTS prefixes (
    prefix String,
    name String
)
PRIMARY KEY prefix
SOURCE(CLICKHOUSE(QUERY 'SELECT network AS prefix, network AS name FROM default.networks'))
LAYOUT(IP_TRIE)
LIFETIME(3600);

CREATE TABLE IF NOT EXISTS flows_raw
(
    date Date,

    type Int32,
    time_received DateTime,
    sequence_num UInt32,
    sampling_rate UInt64,
    flow_direction UInt32,

    sampler_address String,

    time_flow_start DateTime,
    time_flow_end DateTime,

    bytes UInt64,
    packets UInt64,

    src_addr String,
    dst_addr String,

    etype UInt32,

    proto UInt32,

    src_port UInt32,
    dst_port UInt32,

    forwarding_status UInt32,
    tcp_flags UInt32,
    icmp_type UInt32,
    icmp_code UInt32,

    fragment_id UInt32,
    fragment_offset UInt32,

    src_prefix String,
    dst_prefix String
) ENGINE = MergeTree()
PARTITION BY date
ORDER BY time_received;

CREATE FUNCTION getPrefixName AS (etype, addr) -> 
    multiIf(
        etype = 0x0800, dictGetOrDefault('prefixes', 'name', toIPv4(addr), ''),
        etype = 0x86DD, dictGetOrDefault('prefixes', 'name', IPv6StringToNum(addr), ''),
        ''
    );

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_raw_view TO flows_raw AS
    SELECT
        toDate(time_received) AS date,
        getPrefixName(etype, src_addr) AS src_prefix,
        getPrefixName(etype, dst_addr) AS dst_prefix,
        *
    FROM flows;

CREATE VIEW IF NOT EXISTS pretty_flows_raw AS
    SELECT
        time_received,
        time_flow_start,
        time_flow_end,
        sampler_address,
        sampling_rate,
        bytes,
        packets,
        src_addr,
        dst_addr,
        transform(etype, [0x0800, 0x0806, 0x86DD], ['ipv4', 'arp', 'ipv6'], 'unknown') AS etype,
        transform(proto, [0x01, 0x06, 0x11, 0x3a], ['icmp', 'tcp', 'udp', 'icmp'], 'unknown') AS proto,
        src_port,
        dst_port,
        arrayMap(x -> transform(x, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512], ['fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ecn', 'cwr', 'nonce', 'reserved'], 'unknown'), bitmaskToArray(tcp_flags)) as tcp_flags,
        transform(forwarding_status, [0, 1, 2, 3], ['unknown', 'forwarded', 'dropped', 'consumed'], 'unknown') AS forwarding_status,
        fragment_offset > 0 AS is_fragment,
        src_prefix,
        dst_prefix,
        multiIf(
            src_prefix != '' AND dst_prefix != '', 'internal',
            src_prefix != '' AND dst_prefix = '', 'outgoing',
            src_prefix = '' AND dst_prefix != '', 'incoming',
            'unknown'
        ) AS direction
    FROM flows_raw
    ORDER BY time_received DESC;
