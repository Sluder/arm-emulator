#!/usr/bin/python

from capstone import *
from elftools.elf.elffile import ELFFile

if __name__ == '__main__':
    with open('CAN_Receive.ino.elf', 'rb') as f:
        elf = ELFFile(f)

        code = elf.get_section_by_name('.text')

        cap = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

        for i in cap.disasm(code.data(), 0x0008000):
            print('0x{} : {} \t {}'.format(hex(i.address)[2:].zfill(8), i.mnemonic, i.op_str))
