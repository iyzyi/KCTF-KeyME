#pragma once
#ifndef _AES_H_
#define _AES_H_

#include<cstring>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include "anti-debug.h"

using namespace std;

class AES
{
private:
	int Nb;
	int Nk;
	int Nr;

	unsigned int blockBytesLen;

	void SubBytes(unsigned char **state);

	void ShiftRow(unsigned char **state, int i, int n);    // shift row i on n positions

	void ShiftRows(unsigned char **state);

	unsigned char xtime(unsigned char b);    // multiply on x

	unsigned char mul_bytes(unsigned char a, unsigned char b);

	void MixColumns(unsigned char **state);

	void MixSingleColumn(unsigned char *r);

	void AddRoundKey(unsigned char **state, unsigned char *key);

	void SubWord(unsigned char *a);

	void RotWord(unsigned char *a);

	void XorWords(unsigned char *a, unsigned char *b, unsigned char *c);

	void Rcon(unsigned char * a, int n);

	void InvSubBytes(unsigned char **state);

	void InvMixColumns(unsigned char **state);

	void InvShiftRows(unsigned char **state);

	unsigned char* PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen);

	unsigned int GetPaddingLength(unsigned int len);

	void KeyExpansion(unsigned char key[], unsigned char w[]);

	void EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[]);

	void DecryptBlock(unsigned char in[], unsigned char out[], unsigned  char key[]);

	void XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len);

public:
	AES(int keyLen = 256, int irreducible_polynomial_num = 299);// 原版283 

	unsigned char *EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen);

	unsigned char *DecryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[]);

	unsigned char *EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen);

	unsigned char *DecryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv);

	unsigned char *EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen);

	unsigned char *DecryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv);

	void printHexArray(unsigned char a[], unsigned int n);


};

uint8_t sbox[16][16] = { 0 };
void s_box_gen(int irreducible_polynomial_num);
const unsigned char sbox_fake[16][16] = {				// 用于欺骗算法识别插件
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char inv_sbox_fake[16][16] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, };

#endif





AES::AES(int keyLen, int irreducible_polynomial_num)
{
	s_box_gen(irreducible_polynomial_num);
	this->Nb = 4;
	switch (keyLen)
	{
	case 128:
		this->Nk = 4;
		this->Nr = 10;
		break;
	case 192:
		this->Nk = 6;
		this->Nr = 12;
		break;
	case 256:
		this->Nk = 8;
		this->Nr = 14;
		break;
	default:
		throw "Incorrect key length";
	}

	blockBytesLen = 4 * this->Nb * sizeof(unsigned char);
}

unsigned char * AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned int &outLen)
{
	outLen = GetPaddingLength(inLen);
	unsigned char *alignIn = PaddingNulls(in, inLen, outLen);
	unsigned char *out = new unsigned char[outLen];
	unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
	KeyExpansion(key, roundKeys);
	for (unsigned int i = 0; i < outLen; i += blockBytesLen)
	{
		EncryptBlock(alignIn + i, out + i, roundKeys);
	}

	delete[] alignIn;
	delete[] roundKeys;

	return out;
}


unsigned char *AES::EncryptCBC(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
	outLen = GetPaddingLength(inLen);
	unsigned char *alignIn = PaddingNulls(in, inLen, outLen);
	unsigned char *out = new unsigned char[outLen];
	unsigned char *block = new unsigned char[blockBytesLen];
	unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
	KeyExpansion(key, roundKeys);
	memcpy(block, iv, blockBytesLen);
	for (unsigned int i = 0; i < outLen; i += blockBytesLen)
	{
		XorBlocks(block, alignIn + i, block, blockBytesLen);
		EncryptBlock(block, out + i, roundKeys);
		memcpy(block, out + i, blockBytesLen);
	}

	delete[] block;
	delete[] alignIn;
	delete[] roundKeys;

	return out;
}


unsigned char *AES::EncryptCFB(unsigned char in[], unsigned int inLen, unsigned  char key[], unsigned char * iv, unsigned int &outLen)
{
	outLen = GetPaddingLength(inLen);
	unsigned char *alignIn = PaddingNulls(in, inLen, outLen);
	unsigned char *out = new unsigned char[outLen];
	unsigned char *block = new unsigned char[blockBytesLen];
	unsigned char *encryptedBlock = new unsigned char[blockBytesLen];
	unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
	KeyExpansion(key, roundKeys);
	memcpy(block, iv, blockBytesLen);
	for (unsigned int i = 0; i < outLen; i += blockBytesLen)
	{
		EncryptBlock(block, encryptedBlock, roundKeys);
		XorBlocks(alignIn + i, encryptedBlock, out + i, blockBytesLen);
		memcpy(block, out + i, blockBytesLen);
	}

	delete[] block;
	delete[] encryptedBlock;
	delete[] alignIn;
	delete[] roundKeys;

	return out;
}


unsigned char * AES::PaddingNulls(unsigned char in[], unsigned int inLen, unsigned int alignLen)
{
	unsigned char *alignIn = new unsigned char[alignLen];
	memcpy(alignIn, in, inLen);
	memset(alignIn + inLen, 0x00, alignLen - inLen);
	return alignIn;
}

unsigned int AES::GetPaddingLength(unsigned int len)
{
	unsigned int lengthWithPadding = (len / blockBytesLen);
	if (len % blockBytesLen) {
		lengthWithPadding++;
	}

	lengthWithPadding *= blockBytesLen;

	return lengthWithPadding;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned  char *roundKeys)
{
	unsigned char **state = new unsigned char *[4];
	state[0] = new unsigned  char[4 * Nb];
	int i, j, round;
	for (i = 0; i < 4; i++)
	{
		state[i] = state[0] + Nb * i;
	}


	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = in[i + 4 * j];
		}
	}

	AddRoundKey(state, roundKeys);

	for (round = 1; round <= Nr - 1; round++)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, roundKeys + round * 4 * Nb);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, roundKeys + Nr * 4 * Nb);

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			out[i + 4 * j] = state[i][j];
		}
	}

	delete[] state[0];
	delete[] state;
}


void AES::SubBytes(unsigned char **state)
{
	int i, j;
	unsigned char t;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			t = state[i][j];
			state[i][j] = sbox[t / 16][t % 16];
		}
	}

}

void AES::ShiftRow(unsigned char **state, int i, int n)    // shift row i on n positions
{
	unsigned char t;
	int k, j, index;
	unsigned char tmp[4];
	for (j = 0; j < Nb; j++) {
		tmp[j] = state[i][(j + n) % Nb];
	}
	memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char **state)
{
	ShiftRow(state, 1, 1);
	ShiftRow(state, 2, 2);
	ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)    // multiply on x
{
	return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}



/* Implementation taken from https://en.wikipedia.org/wiki/Rijndael_mix_columns#Implementation_example */
void AES::MixSingleColumn(unsigned char *r)
{
	bool bDebugged = false;
	__asm {
		MOV EAX, DWORD PTR FS : [0x30]
		MOV AL, BYTE PTR DS : [EAX + 2]
		MOV bDebugged, AL
	}
	if (bDebugged) {
		//MessageBoxA(NULL, "debug", "debug1", MB_OK);
		exit(0);
	}

	unsigned char a[4];
	unsigned char b[4];
	unsigned char c;
	unsigned char h;
	/* The array 'a' is simply a copy of the input array 'r'
	* The array 'b' is each element of the array 'a' multiplied by 2
	* in Rijndael's Galois field
	* a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
	for (c = 0; c<4; c++)
	{
		a[c] = r[c];
		/* h is 0xff if the high bit of r[c] is set, 0 otherwise */
		h = (unsigned char)((signed char)r[c] >> 7); /* arithmetic right shift, thus shifting in either zeros or ones */
		b[c] = r[c] << 1; /* implicitly removes high bit because b[c] is an 8-bit char, so we xor by 0x1b and not 0x11b in the next line */
		b[c] ^= 0x1B & h; /* Rijndael's Galois field */
	}
	r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]; /* 2 * a0 + a3 + a2 + 3 * a1 */
	r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]; /* 2 * a1 + a0 + a3 + 3 * a2 */
	r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]; /* 2 * a2 + a1 + a0 + 3 * a3 */
	r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]; /* 2 * a3 + a2 + a1 + 3 * a0 */
}

/* Performs the mix columns step. Theory from: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step */
void AES::MixColumns(unsigned char** state)
{
	unsigned char *temp = new unsigned char[4];

	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
		{
			temp[j] = state[j][i]; //place the current state column in temp
		}
		MixSingleColumn(temp); //mix it using the wiki implementation
		for (int j = 0; j < 4; ++j)
		{
			state[j][i] = temp[j]; //when the column is mixed, place it back into the state
		}
	}
	delete temp;
}

void AES::AddRoundKey(unsigned char **state, unsigned char *key)
{
	if (CheckDebug_EnumProcess()) {
		//MessageBoxA(NULL, "debug", "debug2", MB_OK);
		exit(0);
	}

	int i, j;
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < Nb; j++)
		{
			state[i][j] = state[i][j] ^ key[i + 4 * j];
		}
	}
}

void AES::SubWord(unsigned char *a)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		a[i] = sbox[a[i] / 16][a[i] % 16];
	}
}

void AES::RotWord(unsigned char *a)
{
	unsigned char c = a[0];
	a[0] = a[1];
	a[1] = a[2];
	a[2] = a[3];
	a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		c[i] = a[i] ^ b[i];
	}
}

void AES::Rcon(unsigned char * a, int n)
{
	int i;
	unsigned char c = 1;
	for (i = 0; i < n - 1; i++)
	{
		c = xtime(c);
	}

	a[0] = c;
	a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(unsigned char key[], unsigned char w[])
{
	unsigned char *temp = new unsigned char[4];
	unsigned char *rcon = new unsigned char[4];

	int i = 0;
	while (i < 4 * Nk)
	{
		w[i] = key[i];
		i++;
	}

	i = 4 * Nk;
	while (i < 4 * Nb * (Nr + 1))
	{
		temp[0] = w[i - 4 + 0];
		temp[1] = w[i - 4 + 1];
		temp[2] = w[i - 4 + 2];
		temp[3] = w[i - 4 + 3];

		if (i / 4 % Nk == 0)
		{
			RotWord(temp);
			SubWord(temp);
			Rcon(rcon, i / (Nk * 4));
			XorWords(temp, rcon, temp);
		}
		else if (Nk > 6 && i / 4 % Nk == 4)
		{
			SubWord(temp);
		}

		JUNKCODE2

			if (CheckDebug_Explorer()) {
				//MessageBoxA(NULL, "debug", "debug11", MB_OK);
				exit(0);
			}

		w[i + 0] = w[i - 4 * Nk] ^ temp[0];
		w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
		w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
		w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
		i += 4;
	}

	delete[]rcon;
	delete[]temp;

}


unsigned char AES::mul_bytes(unsigned char a, unsigned char b) // multiplication a and b in galois field
{
	unsigned char p = 0;
	unsigned char high_bit_mask = 0x80;
	unsigned char high_bit = 0;
	unsigned char modulo = 0x1B; /* x^8 + x^4 + x^3 + x + 1 */


	for (int i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		high_bit = a & high_bit_mask;
		a <<= 1;
		if (high_bit) {
			a ^= modulo;
		}
		b >>= 1;
	}

	return p;
}


void AES::InvMixColumns(unsigned char **state)
{
	unsigned char s[4], s1[4];
	int i, j;

	for (j = 0; j < Nb; j++)
	{
		for (i = 0; i < 4; i++)
		{
			s[i] = state[i][j];
		}
		s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
		s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
		s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
		s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

		for (i = 0; i < 4; i++)
		{
			state[i][j] = s1[i];
		}
	}
}

void AES::InvShiftRows(unsigned char **state)
{
	ShiftRow(state, 1, Nb - 1);
	ShiftRow(state, 2, Nb - 2);
	ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(unsigned char *a, unsigned char * b, unsigned char *c, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
	{
		c[i] = a[i] ^ b[i];
	}
}

void AES::printHexArray(unsigned char a[], unsigned int n)
{
	for (int i = 0; i < n; i++) {
		printf("%02x ", a[i]);
	}
}





/*******************************************************************
* 利用不可约多项式生成S-box和S逆-box 							   *
* https://blog.csdn.net/u011516178/article/details/81221646		   *
********************************************************************/

//GF(2^8)的多项式乘法
uint16_t polynomialMutil(uint8_t a, uint8_t b)
{
	uint16_t tmp[8] = { 0 };
	uint8_t i;
	for (i = 0; i<8; i++)
	{
		tmp[i] = (a << i)*((b >> i) & 0x1);
	}

	tmp[0] = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3] ^ tmp[4] ^ tmp[5] ^ tmp[6] ^ tmp[7];

	return tmp[0];
}

//找到最高位
uint8_t findHigherBit(uint16_t val)
{
	int i = 0;
	while (val)
	{
		i++;
		val = val >> 1;
	}
	return i;
}

//GF(2^8)的多项式除法
uint8_t gf28_div(uint16_t div_ed, uint16_t div, uint16_t *remainder)
{
	uint16_t r0 = 0;
	uint8_t  qn = 0;
	int bitCnt = 0;

	r0 = div_ed;

	bitCnt = findHigherBit(r0) - findHigherBit(div);
	while (bitCnt >= 0)
	{
		qn = qn | (1 << bitCnt);
		r0 = r0 ^ (div << bitCnt);
		bitCnt = findHigherBit(r0) - findHigherBit(div);
	}
	*remainder = r0;
	return qn;
}

//GF(2^8)多项式的扩展欧几里得算法
uint8_t extEuclidPolynomial(uint8_t a, uint16_t m)
{
	uint16_t r0, r1, r2;
	uint8_t  qn, v0, v1, v2, w0, w1, w2;

	r0 = m;
	r1 = a;

	v0 = 1;
	v1 = 0;

	w0 = 0;
	w1 = 1;

	while (r1 != 1)
	{
		qn = gf28_div(r0, r1, &r2);

		v2 = v0^polynomialMutil(qn, v1);
		w2 = w0^polynomialMutil(qn, w1);

		r0 = r1;
		r1 = r2;

		v0 = v1;
		v1 = v2;

		w0 = w1;
		w1 = w2;
	}
	return w1;
}

//S盒字节变换
uint8_t byteTransformation(uint8_t a, uint8_t x)
{
	uint8_t tmp[8] = { 0 };

	for (uint8_t i = 0; i<8; i++)
	{
		tmp[i] = (((a >> i) & 0x1) ^ ((a >> ((i + 4) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ ((a >> ((i + 6) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ ((x >> i) & 0x1)) << i;
	}
	tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
	return tmp[0];
}

//逆S盒字节变换
uint8_t invByteTransformation(uint8_t a, uint8_t x)
{
	uint8_t tmp[8] = { 0 };

	for (uint8_t i = 0; i<8; i++)
	{
		tmp[i] = (((a >> ((i + 2) % 8)) & 0x1) ^ ((a >> ((i + 5) % 8)) & 0x1) ^ ((a >> ((i + 7) % 8)) & 0x1) ^ ((x >> i) & 0x1)) << i;
	}
	tmp[0] = tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
	return tmp[0];
}

//S盒产生
void s_box_gen(int irreducible_polynomial_num)
{
	uint8_t i, j;

	//初始化S盒
	for (i = 0; i<0x10; i++)
	{
		for (j = 0; j<0x10; j++)
		{
			sbox[i][j] = ((i << 4) & 0xF0) + (j&(0xF));
		}
	}

	//求在GF(2^8)域上的逆，0映射到自身
	for (i = 0; i<0x10; i++)
	{
		for (j = 0; j<0x10; j++)
		{
			if (sbox[i][j] != 0)
			{
				sbox[i][j] = extEuclidPolynomial(sbox[i][j], irreducible_polynomial_num);
			}
		}
	}

	//对每个字节做变换
	for (i = 0; i<0x10; i++)
	{
		for (j = 0; j<0x10; j++)
		{
			sbox[i][j] = byteTransformation(sbox[i][j], 0x63);
		}
	}
}