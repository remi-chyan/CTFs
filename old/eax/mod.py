#!/usr/bin/python
from pwn import *
import sys

def GET_CODE(): 
	elf=ELF("./eax")
	special_head=chr(0xa)+chr(0x5)+chr(0x69)+chr(0x3)
	addr=next(elf.search(special_head))
	code=elf.read(addr,0x9849b7f-0x8049a00)
	return code



class emulator(object):
	def __init__(self,IO_input,breakpoint,tracepoint=0):
		self.MEM=[]
		self.code=[]
		self.PC=0
		self.SP=0x80
		self.asm=''
		self.trace=0
		self.breakpoint=breakpoint
		self.tracepoint=tracepoint
		mem_size=0x100
		code=GET_CODE()
		for i in range(mem_size):
			self.MEM.append(0)
		for i in range(min(0x66,len(arg))):
			self.MEM[i]=ord(arg[i])
		for i in range(len(code)):
			self.code.append(code[i])

		self.ins_dic = {0x0:self.void,
						0x1:self.LEAVE,
						0x2:self.BZ,
						0x3:self.PUSH_FROM_MEM,
						0x4:self.DUP,
						0x5:self.POP_TO_MEM,
						0x6:self.PUSH_IMM,
						0x7:self.PUSH_1,
						0x8:self.ADD,
						0x9:self.XOR,
						0xa:self.PUSH_0,
						0xb:self.RD_MEM,
						0xc:self.DOUBLE_POP
						} 

	def void(self,exit=1):
		if exit==0:
			print "trace code as below:"
			print self.asm
		else:
			print "trace code as below:"
			print self.asm
			print "ERROR with ins_type : "+hex(self.ins)
			sys.exit()

	def LEAVE(self):#0x1
		print self.asm
		if self.MEM[self.SP]!=0:
			print "WINNING!!!!!"
		else:
			print "FAILED!"
		sys.exit()
	

	def BZ(self):#0x2
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]
		self.SP-=1
		self.PC+=1
		op2=ord(self.code[self.PC])
		if op2&0x80:
			op2-=0x100
		if op1==0:
			self.asm+=tmp_asm+'bz to '+hex(self.PC+op2+1)+' (true)\n'
			self.PC+=op2	
		else:
			self.asm+=tmp_asm+'bz to '+hex(self.PC+op2+1)+' (false)\n'


	def PUSH_FROM_MEM(self):#0x3
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		self.PC+=1
		self.SP+=1
		op1=ord(self.code[self.PC])
		self.MEM[self.SP]=self.MEM[op1]
		self.asm+=tmp_asm+'push from mem['+hex(op1)+']\n'

	def DUP(self):#0x4
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]
		self.SP+=1
		self.MEM[self.SP]=op1
		self.asm+=tmp_asm+'dup\n'

	def POP_TO_MEM(self):#0x5
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		self.PC+=1
		op1=ord(self.code[self.PC])
		op2=self.MEM[self.SP]
		self.SP-=1
		self.MEM[op1]=op2
		self.asm+=tmp_asm+'pop to mem['+hex(op1)+']\n'

	def PUSH_IMM(self):#0x6
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		self.PC+=1
		self.SP+=1
		op1=ord(self.code[self.PC])
		self.MEM[self.SP]=op1
		self.asm+=tmp_asm+'push '+hex(op1)+'\n'

	def PUSH_1(self):#0x7
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		self.SP+=1
		self.MEM[self.SP]=1
		self.asm+=tmp_asm+'push 1\n'

	def ADD(self):#0x8
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]
		self.SP-=1
		self.MEM[self.SP]+=op1
		self.MEM[self.SP]=self.MEM[self.SP]&0xff
		self.asm+=tmp_asm+'add\n'

	def XOR(self):#0x9
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]&0xff
		self.SP-=1
		self.MEM[self.SP]=(op1^self.MEM[self.SP])&0xff
		self.asm+=tmp_asm+'xor\n'

	def PUSH_0(self):#0xa
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		self.SP+=1
		self.MEM[self.SP]=0
		self.asm+=tmp_asm+'push 0\n'

	def RD_MEM(self):#0xb
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]
		self.MEM[self.SP]=self.MEM[op1]
		self.asm+=tmp_asm+'rd_mem +(get '+hex(self.MEM[self.SP])+')\n'

	def DOUBLE_POP(self):#0xc
		tmp_asm=hex(self.PC)
		tmp_asm+=(5-len(tmp_asm))*' '+':'
		op1=self.MEM[self.SP]
		self.SP-=1
		op2=self.MEM[self.SP]
		self.SP-=1
		self.asm+=tmp_asm+'double pop(value '+hex(op1)+',addr '+hex(op2)+')\n'
		try:
			self.MEM[op2]=op1
		except:
			print self.asm
			sys.exit()
		

	def kernel(self):
		if self.PC==self.tracepoint:
			self.trace=1
		if self.trace==0:
			self.asm=''
		if self.PC in self.breakpoint:
			self.void(0)
			print "BREAK POINT AT "+hex(self.IPC)
			self.asm=''
			str = raw_input("CONTINUE?")
		try:
			self.ins=ord(self.code[self.PC])
		except IndexError:
			print self.asm
			print "PC is "+hex(self.PC)
			print "      out of range"
			sys.exit()
		try:
			self.ins_dic.get(self.ins)()
		except TypeError:
			print self.asm
			print "INS: "+hex(self.ins)
			print "PC:  "+hex(self.PC)
			print "INS TYPE ERROR!"
			sys.exit()
		self.PC+=1

	def run(self):
		print "running!!!"
		while(1):
			self.kernel()

arg='  emulatorsarebadass'

IO_input=chr(0)*2+arg
code=GET_CODE()
p=emulator(IO_input,[],0x70)
p.run()
