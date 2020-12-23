#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<16> ether_type_t;
const ether_type_t TYPE_IPV4 = 0x800;
typedef bit<8> trans_protocol_t;
const trans_protocol_t TYPE_TCP = 6;
const trans_protocol_t TYPE_UDP = 17;

struct custom_metadata_t {
}

struct empty_header_t {
}

struct empty_metadata_t {
}



header ethernet_h {
    bit<48>   dstAddr;
    bit<48>   srcAddr;
    bit<16>   etherType;
}

header tcam_h {
    bit<64>  tcam_key;
    bit<64>  tcam_key2;

}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    //bit<8>   diffserv;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

header tcp_h {
    bit<16> srcport;
    bit<16> dstport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    tcam_h tcam;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    pktgen_timer_header_t timer;
}


header resubmit_h {
    bit<9> port_id;
    bit<48> _pad2;
}

header qlen_h {
    bit<32> qlen_read;
}
struct metadata_t {
    resubmit_h resubmit_data;
    qlen_h qlen_data;
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pktgen_timer_header_t pktgen_timer_hdr = pkt.lookahead<pktgen_timer_header_t>();
        transition select(pktgen_timer_hdr.app_id) {
            1 : parse_pktgen_timer;
            default : parse_no_timer;
        }
    }
    state parse_pktgen_timer {
        pkt.extract(hdr.timer);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_no_timer {
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        pkt.extract(ig_md.resubmit_data);
        transition parse_ethernet;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {




    Register<bit<32>, bit<32>>(4) qlen;
    RegisterAction<bit<32>, bit<32>, bit<32>>(qlen) read_qlen = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };
    action get_qlen(bit<32> idx) {
        ig_md.qlen_data.qlen_read = read_qlen.execute(idx);
    }

    table reg_match {
        key = {
            ig_tm_md.ucast_egress_port : exact;
            //ig_tm_md.qid: exact; if you use multiple queues in a port
        }
        actions = {
            get_qlen;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action resubmit_add_hdr() {
        ig_intr_dprsr_md.resubmit_type = 1;
    }

    table resubmit_ctrl {
        actions = {
            NoAction;
            resubmit_add_hdr;
        }

        default_action = NoAction;
    }

    action drop() {
        ig_intr_dprsr_md.drop_ctl=1;
    }

    action ipv4_forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table ipv4_exact {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 16;
       default_action = drop();
    }

    table timer {
        key = {
            hdr.timer.pipe_id : exact;
            hdr.timer.app_id  : exact;
            hdr.timer.batch_id : exact;
            hdr.timer.packet_id : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            ipv4_forward;
            @defaultonly drop;
        }
        const default_action = drop();
        size = 1024;
    }

    apply {
        reg_match.apply();
        if (hdr.timer.isValid()) {
            timer.apply();
        }
        else if (ig_intr_md.resubmit_flag == 1) {
            // Processing for resubmitted packets //
        }
        else { // This is the first pass, write default values
            ipv4_exact.apply();

            if(ig_md.qlen_data.qlen_read > 4)
                resubmit_ctrl.apply(); //
        }

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {


    Resubmit() resubmit;

    apply {
        if (ig_intr_dprsr_md.resubmit_type == 1) {
            resubmit.emit(ig_md.resubmit_data);
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser SwitchEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

control SwitchEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {



    Register<bit<32>, bit<32>>(4) qlen; 
    RegisterAction<bit<19>, bit<32>, bit<19>>(qlen) read_qlen = {
        void apply(inout bit<19> value, out bit<19> rv) {
            value = eg_intr_md.deq_qdepth;
            rv = value;
        }
    };

    action get_qlen(bit<32> idx) {
        read_qlen.execute(idx);
    }

    table reg_match {
        key = {
            eg_intr_md.egress_port : exact;
        }
        actions = {
            get_qlen;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
        reg_match.apply();
    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
