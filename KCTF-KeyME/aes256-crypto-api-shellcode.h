#pragma once
#include "stdafx.h"
#include <windows.h>
#include <stdint.h>
#include "anti-debug.h"

#pragma warning(disable : 4996)

__declspec(naked) int __stdcall findKernel32Base() {		// 一定要是裸函数啊！！！
	__asm {
		JUNKCODE3
		push esi
		xor eax, eax
		mov eax, fs:[eax + 0x30]
		mov eax, [eax + 0x0c]
		mov esi, [eax + 0x1c]
		lodsd
		mov eax, [eax + 8]
		pop esi
		ret
	}
}

__declspec(naked) int __stdcall hashString(char* symbol) {
	__asm {
		; hashString:
	push esi
		push edi
		mov esi, [esp + 0x0c]

		calc_hash :
		xor edi, edi
		cld

		hash_iter :
	xor eax, eax
		lodsb
		cmp al, ah
		je hash_done
		ror edi, 0x0d
		add edi, eax
		jmp near hash_iter

		hash_done :
	mov eax, edi
		pop edi
		pop esi
		retn 4
	}
}


__declspec(naked) int __stdcall findSymbolByHash(int dllBase, int symHash) {
	__asm {
		JUNKCODE7
		; findSymbolByHash:
		pushad
			mov ebp, [esp + 0x24]
			mov eax, [ebp + 0x3c]
			mov edx, [ebp + eax + 4 + 20 + 96]
			add edx, ebp
			mov ecx, [edx + 0x18]
			mov ebx, [edx + 0x20]
			add ebx, ebp


			search_loop :
		jecxz error_done
			dec ecx
			mov esi, [ebx + ecx * 4]
			add esi, ebp
			push esi
			call hashString
			cmp eax, [esp + 0x28]
			jnz search_loop
			mov ebx, [edx + 0x24]
			add ebx, ebp
			mov cx, [ebx + ecx * 2]
			mov ebx, [edx + 0x1c]
			add ebx, ebp
			mov eax, [ebx + ecx * 4]
			add eax, ebp
			jmp near done

			error_done :
		xor eax, eax

			done :
		mov[esp + 0x1c], eax
			popad
			retn 8
	}
}

// key可以任意长，plain必须长32（这个是写死了的）
__declspec(naked) int __stdcall aes_256(BYTE* plain, char* key_str, int key_len) {
	__asm {
		JUNKCODE4
		push ebp
		mov ebp, esp
		sub esp, 0x100
		call sub_a0
		; db 'advapi32', 0
		_EMIT 0x61
		_EMIT 0x64
		_EMIT 0x76
		_EMIT 0x61
		_EMIT 0x70
		_EMIT 0x69
		_EMIT 0x33
		_EMIT 0x32
		_EMIT 0

		sub_a0:
		pop ebx
			call findKernel32Base
			mov[ebp - 0x4], eax
			push 0xec0e4e8e
			push[ebp - 0x4]
			call findSymbolByHash
			mov[ebp - 0x14], eax; LoadLibraryA

			JUNKCODE1
			lea eax, [ebx]
			push eax
			call[ebp - 0x14]; LoadLibraryA("advapi32")
			mov[ebp - 0x8], eax; advapi32 base address

			push 0x43c28bda
			push[ebp - 0x8]; advapi32 base address
			call findSymbolByHash
			mov[ebp - 0x18], eax; CryptAcquireContextA
			JUNKCODE2
			push 0x4105a130
			push[ebp - 0x8]
			call findSymbolByHash
			mov[ebp - 0x1c], eax; CryptCreateHash

			push 0xc2122629
			push[ebp - 0x8]
			call findSymbolByHash
			mov[ebp - 0x20], eax; CryptHashData

			push 0xb56d274a
			push[ebp - 0x8]
			call findSymbolByHash
			mov[ebp - 0x24], eax; CryptDeriveKey

			push 0xd9242588
			push[ebp - 0x8]
			call findSymbolByHash
			mov[ebp - 0x28], eax; CryptEncrypt



			JUNKCODE4
			; CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)
			push 0xf0000000; CRYPT_VERIFYCONTEXT
			push 0x18; PROV_RSA_AES
			xor eax, eax
			push eax
			push eax
			lea eax, [ebp - 0x30]; &hprov
			mov dword ptr[eax], 0
			push eax
			call[ebp - 0x18]

			JUNKCODE5
			; CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)
			lea eax, [ebp - 0x34]; &hHash
			mov dword ptr[eax], 0
			push eax
			xor eax, eax
			push eax
			push eax
			push 0x800c; CALG_SHA_256
			push[ebp - 0x30]; hProv
			call[ebp - 0x1c]

			JUNKCODE7
			; CryptHashData(hHash, (BYTE*)key_str, len, 0)
			xor eax, eax
			push eax
			push key_len
			push key_str
			push[ebp - 0x34]
			call[ebp - 0x20]

			JUNKCODE8
			; (CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)
				lea eax, [ebp - 0x38]; &hKey
				mov dword ptr[eax], 0
				push eax
				xor eax, eax
				push eax
				push[ebp - 0x34]
				push 0x6610
				push[ebp - 0x30]
				call[ebp - 0x24]


				JUNKCODE9

				; CryptEncrypt(hKey, NULL, false, 0, pbData, &dwDataLen, 32)
				push 32
				mov dword ptr[ebp - 0x40], 32
				lea eax, [ebp - 0x40]; &dwDataLen
				push eax
				push plain
				xor eax, eax
				push eax
				push eax
				push eax
				push[ebp - 0x38]
				call[ebp - 0x28]

				mov esp, ebp
				pop ebp
				retn 0x0c
	}
}