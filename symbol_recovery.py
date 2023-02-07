# coding=utf-8
# IDA Pro 7.6 
# IDA Python3 API

import ida_ua
import ida_funcs
import idc
import struct
import os

sym_file = "/path/to/symbol/file"
vxworks_file_name = "/path/to/vxworks/file"
load_addr = 0x40205000

file_size = os.path.getsize(vxworks_file_name)
ROM_end_addr = file_size + load_addr

def find_sym_str(offset):
    index = 0
    while True:
        if str_table[offset+index] != 0:
            index += 1
        else:
            break
    return str_table[offset: offset+index]

def u32(data):
    '''Big endian'''
    return struct.unpack(">I",data)[0]


with open(sym_file, 'rb') as f:
    sym_file_contents = f.read()


sym_file_size = u32(sym_file_contents[:4])
sym_count = u32(sym_file_contents[4:8])

sym_table_start = 8
str_table_start = sym_count * 8 + 8

sym_table = sym_file_contents[sym_table_start: str_table_start]
str_table = sym_file_contents[str_table_start: ]


sym_results = []

for i in range(0, sym_count * 8, 8):
    single = sym_table[i: i+8]
    sym_type = single[0]
    sym_str_offset = u32(b'\x00'+single[1: 4])
    sym_func_addr = u32(single[4: ])
    sym_name = find_sym_str(sym_str_offset)

    sym_results.append((sym_type, sym_str_offset, sym_func_addr, sym_name.decode('utf-8')))


def makecode(addr, name, flag):
    ida_ua.create_insn(addr)
    ida_funcs.add_func(addr)
    idc.set_name(addr, name, flag)


def my_parser():
    for sym_type, b, sym_func_addr, sym_name in sym_results:
        if sym_type == ord('T'):
            # global function name
            makecode(sym_func_addr, sym_name, idc.SN_CHECK)
            # pass

        elif sym_type == ord('t'): 
            # local function name
            makecode(sym_func_addr, sym_name, idc.SN_LOCAL)
            # idc.set_name(sym_func_addr, sym_name, idc.SN_LOCAL)
            # pass

        elif sym_type == ord('A'):
            pass

        elif sym_type == ord('B'):
            idc.set_name(sym_func_addr, sym_name)
            # pass

        elif sym_type == ord('D'):
            idc.set_name(sym_func_addr, sym_name)
            # pass

        else:
            print(chr(sym_type))

def check_segment():
    address_list = []
    for sym_type, b, address, d in sym_results:
        if sym_type == ord('B'):
            address_list.append(address)
  
    address_list.sort()

    # check the address
    value = u32(idc.get_bytes(address_list[-1], 4))
    if value != 0xffffffff:
        return

    # calc bss end address
    bss_start = (ROM_end_addr + 0x1000) & 0xfffff000
    bss_end = (address_list[-1] + 0x1000) & 0xfffff000
      
    # create bss segment
    idc.AddSeg(bss_start, bss_end, 0, 1, idaapi.saRelPara, idaapi.scPub)

if __name__ == "__main__":
    check_segment()
    my_parser()