#pragma once
// 加密速度极慢，没有现实意义，也就当作ctf题目而已。 
#include "vm_data.h"
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdint.h> 
#include "flower-instruction.h"
#include "anti-debug.h"

struct VmCmd {
	uint32_t and_param;
	uint8_t rubbish_size;	//垃圾指令大小 
	uint8_t xor_index;
	uint8_t reg_byte;
	uint8_t dst;			//目的操作数 
	uint8_t src;			//源操作数 
	uint8_t op_byte;		//六种指令 
	uint8_t other_op_param;
};

uint32_t encrypt_vm(uint32_t plain) {

	uint16_t xor_data[] = { 0x0123, 0x4567, 0x89ab, 0xcdef, 0x0f1e, 0x2d3c, 0x4b5a, 0x6978 };
	int pointer = 0;
	uint32_t reg[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	reg[15] = plain; 		// [ebp+plain]
	JUNKCODE9
		while (pointer < (sizeof(vm_data) / sizeof(vm_data[0]))) {
			JUNKCODE4
				//for (int i = 0; i < 90; i++){
				VmCmd vcmd;
			vcmd.and_param = *(uint32_t*)(vm_data + pointer);
			JUNKCODE2

				DWORD dwDebugPort = 0;
			NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, 4, 0);
			if (dwDebugPort == -1) {
				//MessageBoxA(NULL, "debug", "debug9", MB_OK);
				exit(0);
			}

			vcmd.rubbish_size = (((vcmd.and_param >> 16) & 1) << 1) + ((vcmd.and_param >> 7) & 1);
			JUNKCODE5
				vcmd.xor_index = (((vcmd.and_param >> 27) & 1) << 2) + (((vcmd.and_param >> 19) & 1) << 1) + ((vcmd.and_param >> 8) & 1);
			JUNKCODE3
				vcmd.reg_byte = *(vm_data + pointer + 4) ^ ((xor_data[vcmd.xor_index] >> 8) & 0xff);
			JUNKCODE1
				vcmd.dst = (vcmd.reg_byte >> 4) & 0xf;
			vcmd.src = (vcmd.reg_byte) & 0xf;
			JUNKCODE8
				vcmd.op_byte = *(vm_data + pointer + 4 + 1 + vcmd.rubbish_size) ^ (xor_data[vcmd.xor_index] & 0xff);
			vcmd.other_op_param = *(vm_data + pointer + 4 + 1 + vcmd.rubbish_size + 1);
			uint16_t new_data = ((*(vm_data + pointer + 4)) << 8) + (*(vm_data + pointer + 4 + 1 + vcmd.rubbish_size));
			for (int i = 0; i < 7; i++) {
				JUNKCODE4
					xor_data[i] = xor_data[i + 1];
			}
			xor_data[7] = new_data;
			pointer += 4 + 1 + vcmd.rubbish_size + 1 + 1;

			//printf("0x%x\t%d\t%d\t%d\t%d\t%d\n", vcmd.and_param, vcmd.rubbish_size, vcmd.dst, vcmd.src, vcmd.op_byte, vcmd.other_op_param);

			//打算在这里加个判断 vcmd.op_byte最高位和最低位的花指令。 
			if (vcmd.op_byte & 64) {				//and

													//printf("and $%d, 0x%x\n", vcmd.dst, vcmd.and_param);
				JUNKCODE5
					reg[vcmd.dst] &= vcmd.and_param;

			}
			else if (vcmd.op_byte & 32) {		//shr

												//printf("shr $%d, 0x%x\n", vcmd.dst, vcmd.other_op_param);
				JUNKCODE2
					reg[vcmd.dst] >>= vcmd.other_op_param;

			}
			else if (vcmd.op_byte & 16) {		//shl

												//printf("shl $%d, 0x%x\n", vcmd.dst, vcmd.other_op_param);
				JUNKCODE7
					reg[vcmd.dst] <<= vcmd.other_op_param;

			}
			else if (vcmd.op_byte & 8) {		//xor

												//printf("xor $%d, $%d\n", vcmd.dst, vcmd.src);
				JUNKCODE8


					CONTEXT context;
				HANDLE hThread = GetCurrentThread();
				context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				GetThreadContext(hThread, &context);
				if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
				{
					//MessageBoxA(NULL, "debug", "debug10", MB_OK);
					exit(0);
				}

				reg[vcmd.dst] ^= reg[vcmd.src];

			}
			else if (vcmd.op_byte & 4) {		//mov

												//printf("mov $%d, $%d\n", vcmd.dst, vcmd.src);
				JUNKCODE9
					reg[vcmd.dst] = reg[vcmd.src];

			}
			else if (vcmd.op_byte & 2) {		//add

												//printf("add $%d, $%d\n", vcmd.dst, vcmd.src);
				JUNKCODE1
					reg[vcmd.dst] += reg[vcmd.src];

			}
			//printf("%x %x %x %x %x %x %x %x\n", xor_data[0], xor_data[1],xor_data[2],xor_data[3],xor_data[4],xor_data[5],xor_data[6],xor_data[7]) ;
		}

	return reg[14];		//eax
}