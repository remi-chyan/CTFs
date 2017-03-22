#!/usr/bin/python
from pwn import *
import sys
def GET_CODE(): 
	elf=ELF("./esp")
	special_head=chr(0xde)+chr(0xad)+chr(0xc0)+chr(0xde)
	addr=next(elf.search(special_head))
	code=elf.read(addr,0x603285-0x603070)
	return code

class CPU_state(object):
	def __init__(self,IPC=0,RAX=0,RBX=0,RCX=0,RDX=0,FLAG=0,mem_ptr=0,ISP=0x40):
		self.IPC=IPC
		self.RAX=RAX
		self.RBX=RBX
		self.RCX=RCX
		self.RDX=RDX
		self.FLAG=FLAG
		self.mem_ptr=mem_ptr
		self.ISP=ISP
class simulator(object):
	def __init__(self,CPU_state,code,MEM,breakpoint=-1,tracepoint=0):
		self.code=[]
		self.IPC=CPU_state.IPC
		self.RAX=CPU_state.RAX
		self.RBX=CPU_state.RBX
		self.RCX=CPU_state.RCX
		self.RDX=CPU_state.RDX
		self.FLAG=CPU_state.FLAG
		self.mem_ptr=CPU_state.mem_ptr
		self.ISP=CPU_state.ISP
		self.MEM=[]
		self.stack=[]
		self.asm=''
		self.breakpoint=breakpoint
		self.tracepoint=tracepoint
		self.trace=0
		for i in range(0x64):
			self.MEM.append(chr(0))
		for i in range(0x50):
			self.stack.append('')
		for i in range (0,len(MEM)):
			self.MEM[i]=MEM[i]
		for i in range(len(code)):
			self.code.append(code[i])
		self.ins_dic = {0x0:self.void,
						0x1:self.ADD,
						0x2:self.SUB,
						0x3:self.MUL,
						0x4:self.DIV,
						0x5:self.INC,
						0x6:self.DEC,
						0x7:self.XOR,
						0x8:self.AND,
						0x9:self.PUSH_REG,
						0xa:self.PUSH_IMM,
						0xb:self.POP,
						0xc:self.void,
						0xd:self.READ,
						0xe:self.void,
						0xf:self.GOBACK,
						0x10:self.CMP,
						0x11:self.JN,
						0x12:self.JP,
						0x13:self.JZ,
						0x14:self.INCMEM,
						0x15:self.DECMEM,
						0x16:self.DECODE
						} 


	def void(self,exit=1):
		if exit==0:
			print "trace code as below:"
			print self.asm
			print
			print "  RAX  :"+hex(self.RAX)
			print "  RBX  :"+hex(self.RBX)
			print "  RCX  :"+hex(self.RCX)
			print "  RDX  :"+hex(self.RDX)
			print "  FLAG :"+hex(self.FLAG)
		
		else:

			print "trace code as below:"
			print self.asm
			print
			print "  RAX  :"+hex(self.RAX)
			print "  RBX  :"+hex(self.RBX)
			print "  RCX  :"+hex(self.RCX)
			print "  RDX  :"+hex(self.RDX)
			print "  FLAG :"+hex(self.FLAG)
			
			if self.ins_type==0:
				self.asm+='end\n'
				print "PROGRAM END!"
				sys.exit()
			else:
				print "ERROR with ins_type : "+hex(self.ins_type)
				sys.exit()
		

	def kernel(self):
		if self.IPC==self.tracepoint:
			self.trace=1
		if self.IPC in self.breakpoint:
			print "BREAK POINT AT "+hex(self.IPC)
			self.void(0)
			self.asm=''
			str = raw_input("CONTINUE?")
		try:
			ins=ord(self.code[self.IPC])
		except:
			self.void(0)
			print
			print "IPC out of range"
			print 
			sys.exit()
		self.ins_type=ins-0x66
		if self.ins_type > 0x16:
			self.IPC+=1
			return
		self.ins_dic.get(self.ins_type)()

	def set_Value(self,v):
		v1=ord(self.code[self.IPC+1])
		v1=v1/16
		if v1>3 :
			self.void()
		if v1==0: 
			self.RAX=v
			return 'rax'
		if v1==1:
			self.RBX=v
			return 'rbx'
		if v1==2:
			self.RCX=v
			return 'rcx'
		if v1==3:
			self.RDX=v
			return 'rdx'
		
	def get_first_operand(self):
		v1=ord(self.code[self.IPC+1])
		v1=v1/16
		if v1>4:
			self.void()
		if v1==0:
			res=(self.RAX,'rax')
		if v1==1:
			res=(self.RBX,'rbx')
		if v1==2:
			res=(self.RCX,'rcx')
		if v1==3:
			res=(self.RDX,'rdx')
		if v1==4:
			res=(self.FLAG,'flag')
		return res

	def get_second_operand(self):
		v1=ord(self.code[self.IPC+1])
		v1=v1&0xf
		if v1>4:
			self.void()
		if v1==0:
			res=(self.RAX,'rax')
		if v1==1:
			res=(self.RBX,'rbx')
		if v1==2:
			res=(self.RCX,'rcx')
		if v1==3:
			res=(self.RDX,'rdx')
		if v1==4:
			res=(self.FLAG,'flag')
		return res

	def run(self):
		self.end=0
		print "running!!!!"
		while(self.end==0):
			self.kernel()
		if self.RAX==0:
			print "yes, YOU GET THE FLAG"

	def ADD(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]+op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'add  '+op1[1]+','+op2[1]+'\n'
		
	def SUB(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]-op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'sub  '+op1[1]+','+op2[1]+'\n'

	def MUL(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]*op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'mul  '+op1[1]+','+op2[1]+'\n'

	def DIV(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]/op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'div  '+op1[1]+','+op2[1]+'\n'

	def INC(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		dest=self.set_Value(op1[0]+1)
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'inc  '+op1[1]+'\n'

	def DEC(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		dest=self.set_Value(op1[0]-1)
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'dec  '+op1[1]+'\n'

	def XOR(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]^op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'xor  '+op1[1]+','+op2[1]+'\n'
	
	def AND(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		dest=self.set_Value(op1[0]&op2[0])
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'and  '+op1[1]+','+op2[1]+'\n'

	def PUSH_REG(self):	
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		v=op1[0]
		self.ISP-=4
		for i in range(4):
			self.stack[self.ISP+i]=v&0xf
			v=v/16
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'push_reg  '+op1[1]+'\n'

	def PUSH_IMM(self):	
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		self.ISP-=4
		v1=0
		rate=0x1
		for i in range(4):
			self.stack[self.ISP+i]=self.code[self.IPC+4-i]
			v1+=rate*ord(self.code[self.IPC+4-i])
			rate*=0x100
		self.IPC+=5
		if self.trace==1:
			self.asm+=tmp_asm+'push_imm  '+hex(v1)+'\n'

	def POP(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.stack[self.ISP])+ord(self.stack[self.ISP+1])*0x100+ord(self.stack[self.ISP+2])*0x10000+ord(self.stack[self.ISP+3])*0x1000000
		dest=self.set_Value(v1)
		self.ISP+=4
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'pop  '+dest+'\n'

	

	def READ(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.MEM[self.mem_ptr])
		dest=self.set_Value(v1)
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'read  '+dest+'\n'

	def GOBACK(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.code[self.IPC+1])
		if self.RDX!=0:
			self.RDX-=1
			self.IPC-=v1
		else:
			self.IPC+=2	
		if self.trace==1:
			self.asm+=tmp_asm+'goback  '+hex(v1)+'\n'		

	def CMP(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		op1=self.get_first_operand()
		op2=self.get_second_operand()
		if op1[0]==op2[0]:
			self.FLAG=0
		if op1[0]>op2[0]:
			self.FLAG=1
		if op1[0]<op2[0]:
			self.FLAG=-1
		self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'cmp  '+op1[1]+','+op2[1]+'\n'

	def JN(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.code[self.IPC+1])
		if self.FLAG<0:
			self.IPC+=(2+v1)
		else:
			self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'jn  '+hex(v1)+'\n'

	def JP(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.code[self.IPC+1])
		if self.FLAG>0:
			self.IPC+=(2+v1)
		else:
			self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'jp  '+hex(v1)+'\n'

	def JZ(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		v1=ord(self.code[self.IPC+1])
		if self.FLAG==0:
			self.IPC+=(2+v1)
		else:
			self.IPC+=2
		if self.trace==1:
			self.asm+=tmp_asm+'jz  '+hex(v1)+'\n'

	def INCMEM(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		self.mem_ptr+=1
		self.IPC+=1
		if self.trace==1:
			self.asm+=tmp_asm+'incmem\n'

	def DECMEM(self):
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		self.mem_ptr-=1
		self.IPC+=1
		if self.trace==1:
			self.asm+=tmp_asm+'deccmem\n'

	def DECODE(self): #finished and tested
		tmp_asm=hex(self.IPC)
		tmp_asm+=(5-len(tmp_asm))*" "+":"
		for i in range(1,31):
			self.code[self.IPC+i]=chr(ord(code[self.IPC+i])^0X66)
		self.IPC+=31
		if self.trace==1:
			self.asm+=tmp_asm+'decode\n'

code=GET_CODE()
print "CODE LENGTH: "+hex(len(code))
mem="74756861"+"6F2C6361"+"6E207745"+"20624520"+"66726945"+"6E64733F"
print mem
init=CPU_state()
s=simulator(init,code,mem,[0x1d9],0x1D0)
s.run()
