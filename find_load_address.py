import re,sys,os
import struct
import json

def u32(data):
    '''Big endian'''
    return struct.unpack(">I",data)[0]

def read_file(path):
    fd = open(path,"rb")
    if(not fd):
        print('[-] Open target firmware failed!')
        exit(-1)
    content = fd.read()
    return content

def find_img_addr(path):
    content = read_file(path)
    img_addr_str_offset = content.find(b"img addr")
    if img_addr_str_offset == -1:
        # print('[-] Can\'t find "img addr" string!')
        return 0
    addr_str_offset = img_addr_str_offset + len('img addr: ')
    count = addr_str_offset

    while 1:
        if content[count] == 0:
            break
        elif content[count] == 10:
            break
        else:
            count+=1
    addr = content[addr_str_offset: count]
    if addr:
        # print(hex(eval(addr)))
        return eval(addr)
    else:
        print('[-] Find address failed!')
        return 0

def find_myfirmware_addr(path):
    content = read_file(path)
    myfirmware_str_offset = content.find(b"MyFirmware")
    if myfirmware_str_offset == -1:
        # print('[-] Can\'t find "MyFirmware" string!')
        return 0
    addr_str_offset = myfirmware_str_offset - 0xc0 + 0x18
    addr = u32(content[addr_str_offset: addr_str_offset + 4])
    if addr:
        # print(hex(addr))
        return addr
    else:
        print('[-] Find address failed!')
        return 0

def find_u_boot_image_addr(path):
    content = read_file(path)
    u_boot_image_addr = content.find(b"u-boot image")
    if u_boot_image_addr == -1:
        return 0
    addr_str_offset = u_boot_image_addr - 0x10
    addr = u32(content[addr_str_offset: addr_str_offset + 4])
    if addr:
        return addr
    else:
        print('[-] Find address failed!')
        return 0


def main():
    dirpath = "/path/to/vxworks/"

    result = {
        "file": "",
        "myfirmware_str_addr": "",
        "img_addr_addr": "",
        "uboot_addr": "",
    }

    filelist = os.listdir(dirpath)
    for i in filelist:
        filename = os.path.join(dirpath,i)
        result["file"] = i
        result["img_addr_addr"] = hex(find_img_addr(filename))
        result["myfirmware_str_addr"] = hex(find_myfirmware_addr(filename))
        result["uboot_addr"] = hex(find_u_boot_image_addr(filename))

        r = json.dumps(result)
        print(r)


if __name__ == "__main__":
    main()