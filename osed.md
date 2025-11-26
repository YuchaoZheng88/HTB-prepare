xfreerdp /u:Offsec /p:lab /v:192.168.115.10 /dynamic-resolution

---------------------------------------
Windbg views:
	1. Disassembly 2. Registers 3. Command

---------------------------------------
Windbg cmds:

1.	g

2. 	dds @esp L5

3.	.load narly
	!nmod

4. dc poi(esp+4)

5. s -d 0 L?80000000 41414141
   s -a 0 L?80000000 "This program cannot be run in DOS mode"
   s -[1]b 00400000 00452000 58 c3 (search: pop eax ret)
   s -a 0x0 L?80000000 w00tw00t

6. r (show registers)
   r ecx=41414141

7. bp kernel32!WriteFile
   bl
   bd 0 (disable index 0)
   be 0 (enable index 0)
   bu ole32!WriteStringStream (breakpoint on an unresolved function)
   bp kernel32!WriteFile ".printf \"The number of bytes written is: %p\", poi(esp + 0x0C);.echo;g"
   bp kernel32!WriteFile ".if (poi(esp + 0x0C) != 4) {gc} .else {.printf \"The number of bytes written is 4\";.echo;}"

   ba e 1 kernel32!WriteFile (hardware breakpoint, e (execute), r (read), or w (write))

8. lm m kernel*
9. x kernelbase!CreateProc* (exam symbols)

10. ? 77269bc0  - 77231430
	? 77269bc0 >> 18

11. ? 41414141
	? 0n41414141
	? 0y1110100110111
	.formats 41414141

12. u poi(@esp+0x04) (disassembly from (esp+4) pointed address)

13. !teb

14. !address 01365a5e (information about certain address)
---------------------------------------
Linux cmds:

1.	msf-pattern_create -l 800

2. 	msf-nasm_shell

	
---------------------------------------

Keystone:
	sudo apt install python3-pip
	pip install keystone-engine

---------------------------------------

m-6 (Savant):
	1. esp+4 points to the buffer.
	2. pop eax, ret. to jmp to buffer.
	3. 'GET' at start of buffer change to \xeb\x17\x90\x90,
		which is short jmp next 0x17 bytes. (not work)
	4. another way: httpMethod = b"\x31\xC9\x85\xC9\x0F\x84\x11" + b" /"  # xor ecx, ecx; test ecx, ecx; je 0x17
	(all jmp 0x17 from beginning address of current assembly)
	5.  rather than terminating the HTTP request, we could add an additional buffer after the first carriage return (\r) and new-line (\n) 
	6. Keystone Engine to find additional buffer on heap.
	7. egg hunt .....

---------------------------------------
