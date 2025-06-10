# Find pop pop retn
Find pop pop return in IDA python
```python
print("\n\n")

print("Running POP/POP/RETN Script\n")

addr = get_segm_by_sel(selector_by_name(".text"))
#end = get_segm_end(addr)

def disp(a,b,c,d):
	mneml = print_operand(a,0)
	mnem2 = print_operand(next_head(a),0)
	mnem3 = print_operand(next_head(next_head(a)),0)
	print("0x%08x:" % a,b,mneml,"|",c,mnem2,"|",d,mnem3)

#while addr < end and addr != BADADDR:
while addr != BADADDR:
	addr = next_head(addr)
	opl = print_insn_mnem(addr)
	if str(opl) == "pop":
		#print("0x%08x:" % addr, opl)
		x = next_head(addr)
		op2 = print_insn_mnem(x)
		if str(op2) == "pop":
			#print("0x%08x:" % addr, opl, "|", op2)
			y = next_head(x)
			ret = print_insn_mnem(y)
			if str(ret) == "retn":
			#	print("0x%08x:" % addr, opl, "|", op2, "|", ret)
				disp(addr,opl,op2,ret)


print("\nScript Finished!\n\n")
```

# find functions of bandlist
```python
import idaapi, idautils, idc
import difflib

checked =[]
bannedList = (["strcpy", "sprintf", "strncpy", "strncat", "StrCpyW", "IstrcpyA"])

def iatCallback(addr, name, ord):
	if any(name.startswith(banned) for banned in bannedList) and name not in checked:
		checked.append(name)
		print("Foundfunction %s in IAT at 0x%08x" % (name, addr))
	return True

for i in range(0, idaapi.get_import_module_qty()):
	name = idaapi.get_import_module_name(i)
	idaapi.enum_import_names(i, iatCallback)

# return is: Foundfunction strcpy@@GLIBC_2.2.5 in IAT at 0x55555555b570
```
