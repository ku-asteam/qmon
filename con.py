import sys
import os
sde_install = os.environ['SDE_INSTALL']
sys.path.append('%s/lib/python2.7/site-packages/tofino'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages/p4testutils'%(sde_install))
sys.path.append('%s/lib/python2.7/site-packages'%(sde_install))
import grpc
import time
import datetime
import bfrt_grpc.client as gc
import port_mgr_pd_rpc as mr
from time import sleep
import socket, struct
import binascii


def hex2ip(hex_ip):
    addr_long = int(hex_ip,16)
    hex(addr_long)
    hex_ip = socket.inet_ntoa(struct.pack(">L", addr_long))
    return hex_ip

# Convert IP to bin
def ip2bin(ip):
    ip1 = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

# Convert IP to hex
def ip2hex(ip):
    ip1 = ''.join([hex(int(x)+256)[3:] for x in ip.split('.')])
    return ip1

def table_add(target, table, keys, action_name, action_data=[]):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
                                  action_name)]
    table.entry_add(target, keys, datas)

def table_mod(target, table, keys, action_name, action_data=[]):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]
    datas = [table.make_data([gc.DataTuple(*p) for p in action_data],
                                  action_name)]
    table.entry_mod(target, keys, datas)

def table_del(target, table, keys):
    table.entry_del(target, keys)

def table_print(target, table, keys):
    keys = [table.make_key([gc.KeyTuple(*f)   for f in keys])]

    for data,key in table.entry_get(target,keys):

        key_fields = key.to_dict()
        data_fields = data.to_dict()

        return data_fields[b'$PORT_UP']

def table_clear(target, table):
    keys = []
    for data,key in table.entry_get(target):
        if key is not None:
            keys.append(key)
    table.entry_del(target, keys)

def fill_table_with_junk(target, table, table_size):
    table_clear(target, table)
    for i in range(table_size):
        table_add(target, table,[("hdr.qmon.qmon_key", i)],"qmon_forward",[("port",152)]) # 104
try:

    grpc_addr = "localhost:50052" # ToDo: IP address of switch 1
    client_id = 0
    device_id = 0
    pipe_id = 0xFFFF
    is_master = True
    client = gc.ClientInterface(grpc_addr, client_id, device_id,is_master)
    target = gc.Target(device_id, pipe_id)
    client.bind_pipeline_config("qmon")
    ipv4_exact = client.bfrt_info_get().table_get("pipe.SwitchIngress.ipv4_exact")
    resubmit_ctrl  = client.bfrt_info_get().table_get("pipe.SwitchIngress.resubmit_ctrl")
    reg_match = client.bfrt_info_get().table_get("pipe.SwitchIngress.reg_match")
    qlen = client.bfrt_info_get().table_get("pipe.SwitchIngress.qlen")
    reg_match_egress = client.bfrt_info_get().table_get("pipe.SwitchEgress.reg_match")
    qlen_egress = client.bfrt_info_get().table_get("pipe.SwitchEgress.qlen")
    table3 = client.bfrt_info_get().table_get("$PORT")
    table_clear(target, ipv4_exact)
    table_clear(target, resubmit_ctrl)
    table_clear(target, reg_match)
    table_clear(target, reg_match_egress)



    table_add(target, reg_match,[("ig_tm_md.ucast_egress_port", 128)],"get_qlen",[("idx", 0)])
    table_add(target, reg_match,[("ig_tm_md.ucast_egress_port", 136)],"get_qlen",[("idx", 1)])
    table_add(target, reg_match,[("ig_tm_md.ucast_egress_port", 144)],"get_qlen",[("idx", 2)])
    table_add(target, reg_match,[("ig_tm_md.ucast_egress_port", 152)],"get_qlen",[("idx", 3)])

    table_add(target, reg_match_egress,[("eg_intr_md.egress_port", 128)],"get_qlen",[("idx", 0)])
    table_add(target, reg_match_egress,[("eg_intr_md.egress_port", 136)],"get_qlen",[("idx", 1)])
    table_add(target, reg_match_egress,[("eg_intr_md.egress_port", 144)],"get_qlen",[("idx", 2)])
    table_add(target, reg_match_egress,[("eg_intr_md.egress_port", 152)],"get_qlen",[("idx", 3)])


    action_data = resubmit_ctrl.make_data(
        [],
        action_name="resubmit_add_hdr"
    )


    while True:
        for i in [0x3]:
            resp = qlen_egress.entry_get(
                target,
                [qlen_egress.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                {"from_hw": True})
            queue_length = next(resp)[0].to_dict()["SwitchEgress.qlen.f1"][1]
            if queue_length != 113:
                #print queue_length
                qlen.entry_add(
                    target,
                    [qlen.make_key([gc.KeyTuple('$REGISTER_INDEX', i)])],
                    [qlen.make_data(
                        [gc.DataTuple('SwitchIngress.qlen.f1', queue_length)])])

                resp = qlen.entry_get(
                    target,
                    [qlen.make_key([gc.KeyTuple('$REGISTER_INDEX', 0x3)])],
                    {"from_hw": True})
                data_dict = next(resp)[0].to_dict()["SwitchIngress.qlen.f1"][1]
                print data_dict

finally:
    client._tear_down_stream()
