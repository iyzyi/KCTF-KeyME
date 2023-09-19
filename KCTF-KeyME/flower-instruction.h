#pragma once

/* JZ 3; JNZ 1; E8(CALL的第一个字节) */
#define JUNKCODE1 __asm {	\
	__asm _EMIT 0x74		\
	__asm _EMIT 0x03		\
	__asm _EMIT 0x75		\
	__asm _EMIT 0x01		\
	__asm _EMIT 0xe8		\
}

/* XOR EAX, EAX; JZ 1; E9(JMP的第一个字节)*/
#define JUNKCODE2 __asm {	\
	__asm _EMIT 0x33		\
	__asm _EMIT 0xc0		\
	__asm _EMIT 0x74		\
	__asm _EMIT 0x01		\
	__asm _EMIT 0xe9		\
}

/* JMP -1; INC EAX; DEX. EAX*/
#define JUNKCODE3 __asm {	\
	__asm _EMIT 0xeb		\
	__asm _EMIT 0xff		\
	__asm _EMIT 0xc0		\
	__asm _EMIT 0x48		\
}

// 这个很牛逼
#define JUNKCODE4 __asm {	\
	__asm _EMIT 0x66		\
	__asm _EMIT 0xb8		\
	__asm _EMIT 0xeb		\
	__asm _EMIT 0x05		\
	__asm _EMIT 0x31		\
	__asm _EMIT 0xc0		\
	__asm _EMIT 0x74		\
	__asm _EMIT 0xfa		\
	__asm _EMIT 0xe8		\
}


/* http://www.vevb.com/wen/2019/09-10/1482.html 单纯的垃圾指令，ida可以正常反编译*/
#define JUNKCODE5 __asm {				\
	__asm push ebp						\
	__asm mov ebp, esp					\
	__asm PUSH -1						\
	__asm PUSH 0						\
	__asm PUSH 0						\
	__asm MOV EAX, DWORD PTR FS : [0]	\
	__asm PUSH EAX						\
	__asm MOV DWORD PTR FS : [0], ESP	\
	__asm SUB ESP, 68					\
	__asm PUSH EBX						\
	__asm PUSH ESI						\
	__asm PUSH EDI						\
	__asm POP EAX						\
	__asm POP EAX						\
	__asm POP EAX						\
	__asm ADD ESP, 68					\
	__asm POP EAX						\
	__asm MOV DWORD PTR FS : [0], EAX	\
	__asm POP EAX						\
	__asm POP EAX						\
	__asm POP EAX						\
	__asm POP EAX						\
	__asm MOV EBP, EAX					\
}

// 单纯的垃圾指令，ida可以正常反编译
#define JUNKCODE6 __asm {		\
	__asm push ebp				\
	__asm mov ebp, esp			\
	__asm push - 1				\
	__asm push 111111			\
	__asm push 222222			\
	__asm mov eax, fs:[0]		\
	__asm push eax				\
	__asm mov fs : [0], esp		\
	__asm pop eax				\
	__asm mov fs : [0], eax		\
	__asm pop eax				\
	__asm pop eax				\
	__asm pop eax				\
	__asm pop eax				\
	__asm mov ebp, eax			\
}

/* call eax */
#define JUNKCODE7 __asm {	\
	__asm _EMIT 0xe8		\
	__asm _EMIT 0x03		\
	__asm _EMIT 0x00		\
	__asm _EMIT 0x00		\
	__asm _EMIT 0x00		\
							\
	__asm clc				\
	__asm _EMIT 0x73		/* jnb */	\
	__asm _EMIT 7			\
							\
	__asm push eax			\
	__asm mov eax, [esp + 4]\
	__asm call eax			\
							\
	__asm mov eax, [esp + 4]\
	__asm add esp, 12		\
}


/* retn流氓指令 */
#define JUNKCODE8 	__asm {		\
	__asm _EMIT 0xe8			\
	__asm _EMIT 0x01			\
	__asm _EMIT 0x00			\
	__asm _EMIT 0x00			\
	__asm _EMIT 0x00			\
	__asm _EMIT 0xe9			\
	__asm add[esp], 6			\
	__asm retn					\
}

/* 破坏栈帧分析 */
#define JUNKCODE9 	__asm {		\
	__asm cmp esp, 0x1000		\
	__asm _EMIT 0x7c		/* jl */	\
	__asm _EMIT 0x5				\
								\
	__asm _EMIT 0xe9		/* jmp */	\
	__asm _EMIT 0x06			\
	__asm _EMIT 0x00			\
	__asm _EMIT 0x00			\
	__asm _EMIT 0x00			\
								\
	__asm add esp, 0x104		\
								\
	__asm inc eax				\
	__asm dec eax				\
}