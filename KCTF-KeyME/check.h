// KCTF-check.cpp : 验证用户名和注册码
//

#include "stdafx.h"
#include <stdint.h>
#include <windows.h>
#include <math.h>
#include "md5.h"
#include "qixi-vm.h"
#include "AES-varitey.h"
#include "aes256-crypto-api-shellcode.h"
#include "flower-instruction.h"
#include "anti-debug.h"

#pragma warning(disable : 4996)


// 第一部分的函数
void QiXiVmEncrypt(uint32_t* step1_3, uint32_t* step1_4) {
	for (int i = 0; i < 8; i++) {
		step1_4[i] = encrypt_vm(step1_3[i]);
	}
}

int aes256_shellcode(uint8_t* step1_3, uint8_t* step1_2)
{
	BYTE pbData[32];
	for (int i = 0; i < 32; i++) {
		pbData[i] = step1_3[i];
	}

	bool bDebugged = false;
	__asm {
		MOV EAX, DWORD PTR FS : [0x30]
		MOV AL, BYTE PTR DS : [EAX + 2]
		MOV bDebugged, AL
	}
	if (bDebugged) {
		//MessageBoxA(NULL, "debug", "debug3", MB_OK);
		exit(0);
	}

	//BYTE* key = (BYTE*)key_str;
	char key[] = "1_L0V3_BXS_F0REVER!";
	aes_256(pbData, key, strlen(key));

	PBYTE pCC = (PBYTE)MessageBoxW;
	if (*pCC == 0xCC) {
		//MessageBoxA(NULL, "debug", "debug4", MB_OK);
		exit(0);
	}

	for (int i = 0; i < 32; i++) {
		step1_2[i] = pbData[i];
	}
	return 0;
}

const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);
uint8_t* AES_variety_encode(uint8_t* plain, uint8_t* key) {
	AES aes(256);
	unsigned int len = 0;
	uint8_t* cipher = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key, len);
	return cipher;
}

bool Step1Check(uint8_t* user_md5_part1_md5, uint8_t* step1_0) {
	for (int i = 0; i < 16; i++) {
		if (user_md5_part1_md5[i] != step1_0[i]) {
			return false;
		}
	}
	return true;
}



// 第二部分的函数
bool CodeDivisionMultiplexingDecode(uint8_t* step2_3, uint8_t* step2_2) {		//码分复用解码
	memset(step2_2, 0, 32);					//这里把我坑死了。。。

	int seq1[] = { -1, -1, -1, +1, +1, -1, +1, +1 };
	int seq2[] = { -1, -1, +1, -1, +1, +1, +1, -1 };
	int seq3[] = { -1, +1, -1, +1, +1, +1, -1, -1 };
	int seq4[] = { -1, +1, -1, -1, -1, -1, +1, -1 };

	int i, j, k;
	int8_t decoded2[8][8][8];

	for (i = 0; i < 8; i++) {

		CONTEXT context;
		HANDLE hThread = GetCurrentThread();
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		GetThreadContext(hThread, &context);
		if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
		{
			//MessageBoxA(NULL, "debug", "debug5", MB_OK);
			exit(0);
		}

		for (j = 0; j < 8; j++) {
			decoded2[i][j][0] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 0) >> 5) & 0x7) * 2 - 4;
			JUNKCODE1
				decoded2[i][j][1] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 0) >> 2) & 0x7) * 2 - 4;
			JUNKCODE2
				decoded2[i][j][2] = (((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 0) << 1) & 0x7) + ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 1) >> 7) & 0x1)) * 2 - 4;
			JUNKCODE3
				decoded2[i][j][3] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 1) >> 4) & 0x7) * 2 - 4;
			JUNKCODE4
				decoded2[i][j][4] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 1) >> 1) & 0x7) * 2 - 4;


			DWORD dwDebugHandle = 0;
			NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E, &dwDebugHandle, 4, 0);
			if (dwDebugHandle != 0) {
				//MessageBoxA(NULL, "debug", "debug6", MB_OK);
				exit(0);
			}


			JUNKCODE5
				decoded2[i][j][5] = (((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 1) << 2) & 0x7) + ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 2) >> 6) & 0x3)) * 2 - 4;
			JUNKCODE6
				decoded2[i][j][6] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 2) >> 3) & 0x7) * 2 - 4;
			JUNKCODE7
				decoded2[i][j][7] = ((*(uint8_t*)(step2_3 + 24 * i + 3 * j + 2)) & 0x7) * 2 - 4;
			JUNKCODE8
				//for (k = 0; k < 8; k++) {
				//	printf("%d ", decoded2[i][j][k]);
				//}
				//printf("\n");
		}
		//printf("\n\n");
	}

	for (i = 0; i < 8; i++) {
		JUNKCODE9
			for (j = 0; j < 8; j++) {
				JUNKCODE4
					int t1 = 0, t2 = 0, t3 = 0, t4 = 0;
				for (k = 0; k < 8; k++) {
					t1 += seq1[k] * decoded2[i][j][k];
					JUNKCODE7
						t2 += seq2[k] * decoded2[i][j][k];
					JUNKCODE2
						t3 += seq3[k] * decoded2[i][j][k];
					JUNKCODE3
						t4 += seq4[k] * decoded2[i][j][k];
					JUNKCODE5
				}

				if ((t1 != -8 && t1 != 8) || (t2 != -8 && t2 != 8) || (t3 != -8 && t3 != 8) || (t4 != -8 && t4 != 8)) {		// 防多解，差一点就被坑了
					return false;
				}

				t1 /= 8; t2 /= 8; t3 /= 8; t4 /= 8;
				JUNKCODE2
					int bit, power = pow(2, 7 - j);
				JUNKCODE6
					bit = (t1 == -1) ? 0 : 1;
				step2_2[i] |= bit * power;
				bit = (t2 == -1) ? 0 : 1;
				step2_2[i + 8] |= bit * power;
				JUNKCODE9
					bit = (t3 == -1) ? 0 : 1;
				step2_2[i + 16] |= bit * power;
				bit = (t4 == -1) ? 0 : 1;
				step2_2[i + 24] |= bit * power;
				JUNKCODE5
			}
	}
	return true;
}


long long ksm(register long long x, register int y)                    //快速幂算法 
{
	int p = 65423;
	if (!y) return 1;
	register long long ret = ksm(x, y >> 1);
	if (y & 1) return ret*ret%p*x%p;
	return ret*ret%p;
}

void GaussianEliminationUnderMod(uint8_t* step2_2, uint8_t* step2_1)		//模意义下的高斯消元
{
	uint16_t sum[16];
	for (int i = 0; i < 16; i++) {
		JUNKCODE9
			sum[i] = step2_2[2 * i] + (step2_2[2 * i + 1] << 8);
		JUNKCODE8
			//printf("%d, ", sum[i]);
	}
	//printf("\n\n");


	DWORD dwDebugPort = 0;
	NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwDebugPort, 4, 0);
	if (dwDebugPort == -1) {
		//MessageBoxA(NULL, "debug", "debug7", MB_OK);
		exit(0);
	}


	int n = 16, p = 65423, maxi;
	long long tmp, ans[110], a[110][110];
	int key[16] = { 233, 136, 189, 132, 157, 100, 196, 185, 138, 222, 90, 101, 115, 229, 161, 97 };

	for (register int i = 1; i <= n; i++)
		for (register int j = 1; j <= n; j++)
			a[i][j] = ksm(key[i - 1], 15 - j + 1);
	for (int i = 1; i <= 16; i++) {
		a[i][17] = sum[i - 1];
	}

	for (register int i = 1; i <= n; i++)
	{
		JUNKCODE3
			if (!a[i][i])//主元不能为0
			{
				maxi = 0;
				for (register int j = i + 1; j <= n && !maxi; j++)
					if (a[j][i]) maxi = j;
				if (!maxi) continue;//如果一整列都为0，不需要消元
				JUNKCODE5
					for (register int j = i; j <= n + 1; j++)
						tmp = a[maxi][j], a[maxi][j] = a[i][j], a[i][j] = tmp;
			}
		for (register int j = i + 1; j <= n; j++)
		{
			tmp = a[j][i];
			if (!tmp) continue;//已经为0，不需要消元
			JUNKCODE1
				for (register int k = i; k <= n + 1; k++)
					a[j][k] = ((a[j][k] * a[i][i] - a[i][k] * tmp) % p + p) % p;
		}
	}
	for (register int i = n; i; i--)
	{
		JUNKCODE6
			for (register int j = i + 1; j <= n; j++)
				a[i][n + 1] = ((a[i][n + 1] - ans[j] * a[i][j]) % p + p) % p;
		ans[i] = a[i][n + 1] * ksm(a[i][i], p - 2) % p;
	}

	for (int i = 0; i < 16; i++) {
		JUNKCODE2
			step2_1[i] = (uint8_t)(ans[i + 1]);
	}
	//for(register int i=0;i<n;i++) printf("%d ",step2_1[i]);
}


unsigned char ROR1(unsigned char x, unsigned char n) {
	JUNKCODE9
		return (x << (8 - (n % 8))) | (x >> (n % 8));
}

bool Step2Check(uint8_t* step2_1, uint8_t* user_md5_part2_md5) {
	unsigned char O[] = { 26, 28, 17, 24, 8, 12, 25, 1, 32, 11, 7, 16, 23, 2, 29, 21, 20, 27, 22, 18, 5, 30, 10, 0, 9, 3, 19, 13, 4, 6, 14, 31 };
	unsigned char K[] = { 21, 23, 22, 20, 19, 12, 4, 18, 3, 6, 16, 14, 10, 24, 28, 15, 31, 0, 11, 5, 8, 26, 13, 32, 30, 29, 17, 9, 25, 2, 1, 27 };
	//unsigned char A[] = { 21, 9, 12, 31, 28, 19, 22, 25, 29, 3, 16, 15, 1, 2, 30, 6, 23, 0, 4, 26, 8, 14, 20, 5, 7, 24, 10, 17, 11, 27, 18, 13};
	unsigned char B[] = { 3, 238, 236, 17, 20, 14, 5, 12, 3, 237, 247, 5, 0, 246, 0, 231, 0, 232, 239, 11, 245, 3, 4, 255, 0, 22, 6, 244, 239, 24, 9, 249 };
	unsigned char C[] = { 23, 38, 241, 179, 134, 72, 110, 16, 154, 191, 181, 79, 233, 101, 15, 62 };
	/*for (int i = 0; i < 32; i++) {
	B[i] = A[i] - H[i];
	printf("%d, ", B[i]);
	}*/
	JUNKCODE9
		uint8_t Temp[16];
	for (int i = 0; i < 16; i++) {
		JUNKCODE7
			Temp[i] = ROR1((step2_1[i] ^ K[i]), O[i]) + B[i] - user_md5_part2_md5[i];
	}
	JUNKCODE4
		uint8_t FinalCheckMD5[16];
	GetMD5(Temp, FinalCheckMD5, 16);
	//for (int i = 0; i < 16; i++) {
	//	printf("%d, ", FinalCheckMD5[i]);
	//}
	JUNKCODE3
		for (int i = 0; i < 16; i++) {
			if (C[i] != FinalCheckMD5[i]) {
				JUNKCODE3
					return false;
			}
		}
	return true;
}


int hex2byte(uint8_t *dst, char *src) {
	while (*src) {
		sscanf(src, "%2x", dst);
		src += 2;
		dst++;
	}
	return 0;
}



bool CheckSerial(char user[], char serial_str[])
{
	if ((strlen(serial_str) != 224 * 2) || (strlen(user) <= 0) || (strlen(user) >= 255)) {
		return false;
	}

	for (int i = 0; i < 224 * 2; i++) {
		if (!((serial_str[i] >= '0' && serial_str[i] <= '9') || (serial_str[i] >= 'a' && serial_str[i] <= 'f'))) {
			return false;
		}
	}

	uint8_t user_md5[16];
	GetMD5((uint8_t*)user, user_md5, strlen(user));

	uint8_t user_md5_part1_md5[16];
	GetMD5(user_md5, user_md5_part1_md5, 8);

	uint8_t user_md5_part2_md5[16];
	GetMD5(user_md5 + 8, user_md5_part2_md5, 8);


	uint8_t serial[224 + 100];		// 只用224的话莫名其妙地破坏了栈，我没去调试了解具体原因。
	hex2byte(serial, serial_str);

	uint8_t step1_4[32];
	uint8_t step2_3[192];
	for (int i = 0; i < 32; i++) {
		step1_4[i] = serial[i];
	}
	for (int i = 0; i < 192; i++) {
		step2_3[i] = serial[i + 32];
	}


	// 第一部分
	uint8_t step1_3[32];
	QiXiVmEncrypt((uint32_t*)step1_4, (uint32_t*)step1_3);

	uint8_t step1_2[32];
	aes256_shellcode(step1_3, step1_2);

	uint8_t step1_1[16];
	for (int i = 0; i < 16; i++) {
		if ((uint8_t)(step1_2[i * 2] + 0x7f) != step1_2[i * 2 + 1]) {
			//printf("0x%x 0x%x 0x%x\n", step1_2[i * 2], step1_2[i * 2 + 1], (uint8_t)(step1_2[i * 2] + 0x7f));
			return false;
		}
		step1_1[i] = step1_2[2 * i];
	}

	uint8_t key1[32] = { 87,111,32,89,111,110,103,89,117,97,110,32,88,105,72,117,97,110,32,75,97,110,88,117,110,32,76,117,110,84,97,110 };//Wo YongYuan XiHuan KanXun LunTan
	uint8_t* step1_0 = AES_variety_encode(step1_1, key1);		// len = 16

	bool check1 = Step1Check(user_md5_part1_md5, step1_0);



	// 第二部分
	uint8_t step2_2[32];
	if (!CodeDivisionMultiplexingDecode(step2_3, step2_2)) {
		return false;
	}

	uint8_t step2_1[16];
	GaussianEliminationUnderMod(step2_2, step2_1);



	// 时间检测
	LARGE_INTEGER startTime, endTime;
	QueryPerformanceCounter(&startTime);

	bool check2 = Step2Check(step2_1, user_md5_part2_md5);

	QueryPerformanceCounter(&endTime);
	int time = endTime.QuadPart - startTime.QuadPart;
	if (time > 100) {
		//MessageBoxA(NULL, "debug", "debug8", MB_OK);
		exit(0);
	}
	// 时间检测




	return check1 && check2;
}