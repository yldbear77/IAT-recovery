#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

#define DEF_SECTION_NAME1 ".Dong"
#define DEF_SECTION_NAME2 ".Min"
#define DEF_VIRTUAL_SIZE	0x2000
#define DEF_RAWDATA_SIZE1	0x2000
#define DEF_RAWDATA_SIZE2	0x200
#define UNPACK_CODE_OFFSET  0x60


HANDLE hFile, hMap, hHeap;

LPBYTE BasePointer;
LPBYTE Mapped;

DWORD FileSize;

IMAGE_SECTION_HEADER	DongISH, MinISH;


VOID MyPackerIntro(PTCHAR);
BOOL LoadFileToPack(PTCHAR);
BOOL CheckBasicPESpec();
BOOL StartPacking();
BOOL CreateSection(PIMAGE_NT_HEADERS, PIMAGE_FILE_HEADER, PIMAGE_OPTIONAL_HEADER, PIMAGE_SECTION_HEADER, PIMAGE_FILE_HEADER, PIMAGE_OPTIONAL_HEADER);
BOOL IDTBackUp(PIMAGE_OPTIONAL_HEADER, DWORD, LPDWORD);
BOOL FuncNameBackUp(PIMAGE_OPTIONAL_HEADER, DWORD, LPDWORD);
BOOL RemoveAndWriteIDT(PIMAGE_OPTIONAL_HEADER, DWORD);
BOOL InsertUnpackCode(PIMAGE_FILE_HEADER, PIMAGE_SECTION_HEADER, PIMAGE_OPTIONAL_HEADER, DWORD);
BOOL CreatePackedFile(PTCHAR);
DWORD RVAtoRAW(DWORD);
DWORD RAWtoRVA(DWORD);
BOOL GetFuncName(HMODULE, WORD, PCHAR);


int _tmain(DWORD argc, PTCHAR argv[])
{
	if (argc != 2)
	{
		_tprintf(L"Usage : %s [FILE_PATH]\n", argv[0]);
		return 1;
	}

	MyPackerIntro(argv[1]);
	if (LoadFileToPack(argv[1]) || CheckBasicPESpec() || StartPacking() || CreatePackedFile(argv[1]))
	{
		printf("\n[#] Packing Failed !\n");
		return 1;
	}

	printf("\n[#] Packing Completed !\n");
	return 0;
}

VOID MyPackerIntro(PTCHAR FileName)
{
	printf("========================= DM-PACKER ==========================\n");
	printf("| This packer only can be used to pack exe file. I made this |\n");
	printf("| for studying only. Thank you for using this packer.	     |\n");
	printf("| Happy Packing and Reversing !              @ Made by knolz |\n");
	printf("==============================================================\n");
}

BOOL LoadFileToPack(PTCHAR FileName)	// ���������� �б��������� Mapped, ��ŷ�Ͽ� ���Ϸ� ������ �޸𸮴� BasePointer
{
	DWORD lpBytesRead;

	hFile = CreateFile(FileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) { printf("[*] File Create Error Occurred ! [CODE %d]\n", GetLastError()); return 1; }

	hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL) { printf("[*] File Mapping Error Occurred ! [CODE %d]\n", GetLastError()); return 1; }

	FileSize = GetFileSize(hFile, NULL);

	Mapped = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, FileSize);
	if (Mapped == NULL) { printf("[*] File MapView Failed ! [CODE %d]\n", GetLastError()); return 1; }

	hHeap = GetProcessHeap();

	BasePointer = (LPBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, FileSize + sizeof(IMAGE_SECTION_HEADER) * 2 + DEF_RAWDATA_SIZE1 + DEF_RAWDATA_SIZE2);
	if (BasePointer == NULL) { printf("[*] Memory Allocate Error [CODE %d]\n", GetLastError()); return 1; }

	ReadFile(hFile, BasePointer, FileSize, &lpBytesRead, NULL);

	return 0;
}

BOOL CheckBasicPESpec()		// PE������ ���� ���ʰ� �Ǵ� ���� üũ, ��߳��� ������ü�� �ȵ�
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeader;

	pDOSHeader = (PIMAGE_DOS_HEADER)Mapped;										// "MZ" üũ
	if (IMAGE_DOS_SIGNATURE != pDOSHeader->e_magic) { printf("[*] IMAGE_DOS_SIGNATURE is not detected.\n"); return 1; }

	pNTHeader = (PIMAGE_NT_HEADERS)(Mapped + pDOSHeader->e_lfanew);				// "PE" üũ
	if (IMAGE_NT_SIGNATURE != pNTHeader->Signature) { printf("[*] IMAGE_NT_SIGNATURE is not detected.\n"); return 1; }

	return 0;
}

BOOL StartPacking()
{
	// �б� ���� ���ε� ��������
	PIMAGE_DOS_HEADER			pDOSHeader = (PIMAGE_DOS_HEADER)Mapped;
	PIMAGE_NT_HEADERS			pNTHeader = (PIMAGE_NT_HEADERS)(Mapped + pDOSHeader->e_lfanew);
	PIMAGE_FILE_HEADER			pFileHeader = (PIMAGE_FILE_HEADER)(&pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER		pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);
	PIMAGE_SECTION_HEADER		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pOptionalHeader + (pFileHeader->SizeOfOptionalHeader));

	// ���� ������ ��ŷ�� ����
	PIMAGE_DOS_HEADER			pNewIDH = (PIMAGE_DOS_HEADER)BasePointer;
	PIMAGE_NT_HEADERS			pNewINH = (PIMAGE_NT_HEADERS)(BasePointer + pNewIDH->e_lfanew);
	PIMAGE_FILE_HEADER			pNewIFH = (PIMAGE_FILE_HEADER)(&pNewINH->FileHeader);
	PIMAGE_OPTIONAL_HEADER		pNewIOH = (PIMAGE_OPTIONAL_HEADER)(&pNewINH->OptionalHeader);

	// ������, Ŀ��
	DWORD IDTOffset = RVAtoRAW(pOptionalHeader->DataDirectory[0x1].VirtualAddress);
	DWORD WrittenByte = 0;

	if (CreateSection(pNTHeader, pFileHeader, pOptionalHeader, pSectionHeader, pNewIFH, pNewIOH))
		return 1;
	if (IDTBackUp(pOptionalHeader, IDTOffset, &WrittenByte) || FuncNameBackUp(pOptionalHeader, IDTOffset, &WrittenByte))
		return 1;
	if (RemoveAndWriteIDT(pNewIOH, IDTOffset) || InsertUnpackCode(pFileHeader, pSectionHeader, pNewIOH, IDTOffset))
		return 1;

	return 0;
}

BOOL CreateSection(PIMAGE_NT_HEADERS pNTHeader, PIMAGE_FILE_HEADER pFileHeader, PIMAGE_OPTIONAL_HEADER pOptionalHeader, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_FILE_HEADER pNewIFH, PIMAGE_OPTIONAL_HEADER pNewIOH)
{
	PIMAGE_SECTION_HEADER		bkupSectionHeader = pSectionHeader;

	DWORD DosStubSize, BoundImportTableSize;
	DWORD HeaderPaddingOffset, BoundImportTableOffset, NewSectionHeaderOffset;
	DWORD ByteToAlloc, peBodySize = 0;

	INT Counter;

	printf("[*] Creating new section ");
	// ù ��°�� �� ��° ���� �ʱ�ȭ ���� ...................................................................................

	memset(&DongISH, 0x00, sizeof(IMAGE_SECTION_HEADER));
	memset(&MinISH, 0x00, sizeof(IMAGE_SECTION_HEADER));

	strcpy((PCHAR)DongISH.Name, DEF_SECTION_NAME1);
	strcpy((PCHAR)MinISH.Name, DEF_SECTION_NAME2);

	DongISH.Misc.VirtualSize = MinISH.Misc.VirtualSize = DEF_VIRTUAL_SIZE;
	pSectionHeader += (pFileHeader->NumberOfSections - 1);
	DongISH.VirtualAddress = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;

	while (1)
	{
		if (DongISH.VirtualAddress % pOptionalHeader->SectionAlignment == 0)
			break;

		(DongISH.VirtualAddress)++;
	}

	DongISH.PointerToRawData = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;
	DongISH.SizeOfRawData = DEF_RAWDATA_SIZE1;
	DongISH.Characteristics = IMAGE_SCN_MEM_READ;

	while (1)
	{
		if (DongISH.PointerToRawData % pOptionalHeader->FileAlignment == 0)
			break;

		(DongISH.PointerToRawData)++;
	}

	MinISH.VirtualAddress = DongISH.VirtualAddress + MinISH.Misc.PhysicalAddress;
	MinISH.PointerToRawData = DongISH.PointerToRawData + DongISH.SizeOfRawData;
	MinISH.SizeOfRawData = DEF_RAWDATA_SIZE2;
	MinISH.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;

	pNewIFH->NumberOfSections += 2, pNewIOH->SizeOfImage += DEF_VIRTUAL_SIZE * 2;

	// ......................................................................................................................

	DosStubSize = (DWORD)pNTHeader - (DWORD)(Mapped + sizeof(IMAGE_DOS_HEADER));				// DOS Stub�� ũ��
	HeaderPaddingOffset = sizeof(IMAGE_DOS_HEADER) + DosStubSize + sizeof(IMAGE_NT_HEADERS)		// ��� �� NULL �е� ���� �ּ�
		+ sizeof(IMAGE_SECTION_HEADER)*(pFileHeader->NumberOfSections) + pOptionalHeader->DataDirectory[0xB].Size;
	BoundImportTableSize = pOptionalHeader->DataDirectory[0xB].Size;					// BOUND IMPORT TABLE�� ũ��
	NewSectionHeaderOffset = HeaderPaddingOffset - pOptionalHeader->DataDirectory[0xB].Size;
	pSectionHeader = bkupSectionHeader;

	// ��� 2���� ������ ������ �ִ°� Ȯ��
	if (pOptionalHeader->DataDirectory[0xB].VirtualAddress != 0x00000000)	// BOUND IMPORT TABLE�� �����ϰ�,
	{
		BoundImportTableOffset = RVAtoRAW(pOptionalHeader->DataDirectory[0xB].VirtualAddress);
		memset(BasePointer + BoundImportTableOffset, 0x00, BoundImportTableSize);	// BOUND IMPORT TABLE�� 0���� ��Ʈ

		// PE Header�� Body ���̿� NULL�е��� ������� ��
		if (pOptionalHeader->SizeOfHeaders - HeaderPaddingOffset + BoundImportTableSize < sizeof(IMAGE_SECTION_HEADER) * 2)
		{
			ByteToAlloc = sizeof(IMAGE_SECTION_HEADER) - (pOptionalHeader->SizeOfHeaders - HeaderPaddingOffset + BoundImportTableSize);

			while (1)	// FileAlignment �����ŭ �о��ֱ� ����
			{
				if (ByteToAlloc % pOptionalHeader->FileAlignment == 0)
					break;
				ByteToAlloc++;
			}

			for (Counter = 0; Counter < pFileHeader->NumberOfSections; Counter++, pSectionHeader++)
				peBodySize += pSectionHeader->SizeOfRawData;

			memcpy(BasePointer + pOptionalHeader->SizeOfHeaders + ByteToAlloc, BasePointer + pOptionalHeader->SizeOfHeaders, peBodySize);
			memset(BasePointer + pOptionalHeader->SizeOfHeaders, 0x00, ByteToAlloc);
		}
		pNewIOH->DataDirectory[0xB].VirtualAddress = 0x00000000, pNewIOH->DataDirectory[0xB].Size = 0x00000000;
	}
	else
	{
		if (pOptionalHeader->SizeOfHeaders - HeaderPaddingOffset < sizeof(IMAGE_SECTION_HEADER) * 2)
		{
			ByteToAlloc = pOptionalHeader->SizeOfHeaders - HeaderPaddingOffset;

			while (1)
			{
				if (ByteToAlloc % pOptionalHeader->FileAlignment == 0)
					break;
				ByteToAlloc++;
			}

			for (Counter = 0; Counter < pFileHeader->NumberOfSections; Counter++, pSectionHeader++)
				peBodySize += pSectionHeader->SizeOfRawData;

			memcpy(BasePointer + pOptionalHeader->SizeOfHeaders + ByteToAlloc, BasePointer + pOptionalHeader->SizeOfHeaders, peBodySize);
			memset(BasePointer + pOptionalHeader->SizeOfHeaders, 0x00, ByteToAlloc);
		}
	}

	memcpy(BasePointer + NewSectionHeaderOffset, &DongISH, sizeof(IMAGE_SECTION_HEADER));
	memcpy(BasePointer + NewSectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER), &MinISH, sizeof(IMAGE_SECTION_HEADER));

	printf("............... OK !\n");
	return 0;
}

BOOL IDTBackUp(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD IDTOffset, LPDWORD WrittenByte)	// IDT�� .Dong���� �ű�, ����Ʈ�ϴ� DLL �̸��� ����
{
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(Mapped + IDTOffset);
	DWORD NumberOfDLLs, IDTSize;

	printf("[*] Moving Import Directory Table ");
	for (NumberOfDLLs = 0, IDTSize = 0; pIID->Name != 0x00000000 && pIID->FirstThunk != 0x00000000; NumberOfDLLs++, pIID++)
		IDTSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	pIID = (PIMAGE_IMPORT_DESCRIPTOR)(Mapped + IDTOffset);
	memcpy(BasePointer + DongISH.PointerToRawData, pIID, IDTSize);	// .Dong�� IDT ��� ����
	memset(BasePointer + DongISH.PointerToRawData + IDTSize, 0x00, sizeof(IMAGE_IMPORT_DESCRIPTOR));	// NULL����ü ����

	*WrittenByte = DongISH.PointerToRawData + IDTSize + sizeof(IMAGE_IMPORT_DESCRIPTOR);	// �Լ����� �ű� ������

	printf(".................... OK !\n");
	return 0;
}

BOOL FuncNameBackUp(PIMAGE_OPTIONAL_HEADER pOptionalHeader, DWORD IDTOffset, LPDWORD WrittenByte)	// �Լ��� �ű�
{
	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(Mapped + IDTOffset);
	PIMAGE_IMPORT_BY_NAME    pIIN;

	HMODULE hMod;

	DWORD NameTableOffset;
	DWORD TakeByte = 0;

	WORD Ordinal;

	LPDWORD NameRVA;

	CHAR Name[100];


	printf("[*] Moving function names ");
	while (pIID->Name != 0x00000000 && pIID->FirstThunk != 0x00000000)
	{
		NameTableOffset = RVAtoRAW(pIID->OriginalFirstThunk);
		if (pIID->OriginalFirstThunk == 0x00000000)	// INT�� 0�̶��
			NameTableOffset = RVAtoRAW(pIID->FirstThunk);

		memset(BasePointer + *WrittenByte, 0xDE, sizeof(BYTE)), (*WrittenByte)++;
		memset(BasePointer + *WrittenByte, 0xAD, sizeof(BYTE)), (*WrittenByte)++;

		memcpy(BasePointer + *WrittenByte, BasePointer + RVAtoRAW(pIID->Name), strlen((PCHAR)BasePointer + RVAtoRAW(pIID->Name)));
		*WrittenByte += strlen((PCHAR)BasePointer + RVAtoRAW(pIID->Name));

		memset(BasePointer + *WrittenByte, 0x00, sizeof(BYTE)), *WrittenByte += sizeof(BYTE);

		NameRVA = (LPDWORD)(BasePointer + NameTableOffset);
		while (*NameRVA != 0x00000000)
		{
			pIIN = (PIMAGE_IMPORT_BY_NAME)(BasePointer + RVAtoRAW(*NameRVA));

			if ((*NameRVA & 0x80000000) == 0x80000000)	// Ordinal�� �Լ��� ����Ʈ�Ҷ�
			{
				hMod = LoadLibraryA((LPCSTR)Mapped + RVAtoRAW(pIID->Name));

				Ordinal = (WORD)*NameRVA;
				GetFuncName(hMod, Ordinal, Name);

				memcpy(BasePointer + *WrittenByte, Name, strlen(Name)), *WrittenByte += strlen(Name);
				memset(BasePointer + *WrittenByte, 0x00, sizeof(BYTE)), *WrittenByte += sizeof(BYTE);

				(*NameRVA) = 0x00000000;	// Ordinal ����
			}
			else
			{
				memcpy(BasePointer + *WrittenByte, pIIN->Name, strlen(pIIN->Name)), *WrittenByte += strlen(pIIN->Name);
				memset(BasePointer + *WrittenByte, 0x00, sizeof(BYTE)), *WrittenByte += sizeof(BYTE);

				memset(&pIIN->Hint, 0x00, sizeof(WORD));	// Hint ����
				memset(pIIN->Name, 0x00, strlen(pIIN->Name));	// �Լ��� ����
			}

			memset(BasePointer + RVAtoRAW(pIID->Name), 0x00, strlen((PCHAR)BasePointer + RVAtoRAW(pIID->Name)));	// DLL�̸� ����
			NameRVA++;
		}
		pIID++;
	}

	printf("........................ OK !\n");
	return 0;
}

BOOL RemoveAndWriteIDT(PIMAGE_OPTIONAL_HEADER pNewIOH, DWORD IDTOffset)	// ���� IDT�� ��� �����, KERNEL32.dll�� ����Ʈ �׸��� LoadLibrary, GetProcAddress�� IAT�� ����
{
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	IMAGE_IMPORT_DESCRIPTOR KERNEL32;

	DWORD TakeByte = 0;
	DWORD IDTSize = 0;
	DWORD posLoadLibraryA, posGetProcAddress, posExitProcess, posVirtualProtect;
	DWORD posIAT, IATval;


	printf("[*] Removing existing Import Directory Table ");

	ZeroMemory(&KERNEL32, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	pIID = (PIMAGE_IMPORT_DESCRIPTOR)(Mapped + IDTOffset);

	// ���� IDT�� ��� ����
	while (pIID->Name != 0x00000000 && pIID->FirstThunk != 0x00000000)
		IDTSize += sizeof(IMAGE_IMPORT_DESCRIPTOR), pIID++;

	memset(BasePointer + IDTOffset, 0x00, IDTSize);

	// KERNEL32.DLL�� .Min�� ��
	memcpy(BasePointer + MinISH.PointerToRawData, "KERNEL32.dll\0", strlen("KERNEL32.dll") + sizeof(BYTE));


	// LoadLibraryA, GetProcAddress, VirtualProtect, ExitProcess�� ��
	posLoadLibraryA = MinISH.PointerToRawData + strlen("KERNEL32.dll") + sizeof(BYTE) + sizeof(DWORD) * 5;
	memcpy(BasePointer + posLoadLibraryA, "\0\0LoadLibraryA\0", strlen("LoadLibraryA") + sizeof(BYTE) * 3);

	posGetProcAddress = posLoadLibraryA + sizeof(BYTE) * 2 + strlen("LoadLibraryA") + sizeof(BYTE);
	memcpy(BasePointer + posGetProcAddress, "\0\0GetProcAddress\0", strlen("GetProcAddress") + sizeof(BYTE) * 3);

	posVirtualProtect = posGetProcAddress + sizeof(BYTE) * 2 + strlen("GetProcAddress") + sizeof(BYTE);
	memcpy(BasePointer + posVirtualProtect, "\0\0VirtualProtect\0", strlen("VirtualProtect") + sizeof(BYTE) * 3);

	posExitProcess = posVirtualProtect + sizeof(BYTE) * 2 + strlen("VirtualProtect") + sizeof(BYTE);
	memcpy(BasePointer + posExitProcess, "\0\0ExitProcess\0", strlen("ExitProcess") + sizeof(BYTE) * 3);


	// IAT�� ��
	posIAT = MinISH.PointerToRawData + strlen("KERNEL32.dll") + sizeof(BYTE);

	IATval = RAWtoRVA(MinISH.PointerToRawData) + 0x21;
	memcpy(BasePointer + posIAT, &IATval, sizeof(DWORD)), posIAT += sizeof(DWORD);

	IATval = RAWtoRVA(MinISH.PointerToRawData) + 0x30;
	memcpy(BasePointer + posIAT, &IATval, sizeof(DWORD)), posIAT += sizeof(DWORD);

	IATval = RAWtoRVA(MinISH.PointerToRawData) + 0x41;
	memcpy(BasePointer + posIAT, &IATval, sizeof(DWORD)), posIAT += sizeof(DWORD);

	IATval = RAWtoRVA(MinISH.PointerToRawData) + 0x52;
	memcpy(BasePointer + posIAT, &IATval, sizeof(DWORD)), posIAT += sizeof(DWORD);

	memset(BasePointer + posIAT, 0x00, sizeof(DWORD));	// NULL������


	// IDT�� �������
	KERNEL32.FirstThunk = RAWtoRVA(MinISH.PointerToRawData) + 0xD;
	KERNEL32.Name = RAWtoRVA(MinISH.PointerToRawData);

	memcpy(BasePointer + IDTOffset, &KERNEL32, sizeof(IMAGE_IMPORT_DESCRIPTOR));


	pNewIOH->DataDirectory[0x1].Size = 0x28;

	printf("............ OK !\n");
	return 0;
}

BOOL InsertUnpackCode(PIMAGE_FILE_HEADER pFileHeader, PIMAGE_SECTION_HEADER pSectionHeader, PIMAGE_OPTIONAL_HEADER pNewIOH, DWORD IDTOffset)	// ������ �������� ����ŷ�ϴ� �ڵ带 ����
{
	PIMAGE_IMPORT_DESCRIPTOR pIID;

	DWORD ImageBase, OriginalEntryPoint;
	DWORD posKERNEL32, posLoadLibraryA, posGetProcAddress, posVirtualProtect, posName;
	DWORD posOrgIDT, posDongIDT, posOrgIAT, posIATRVA, VirtualAddressIDT, IDTSize = 0;
	DWORD IDTSection, IDTSectionSize;
	DWORD GarbageMemory, JumpToMedium, JumpToRealCode, Temp;

	LPBYTE posDecodeSection;

	WORD Counter = 0;


	printf("[*] Inserting unpacking code ");

	// ImageBase ���
	ImageBase = pNewIOH->ImageBase;


	// EP ����, ����ŷ �ڵ尡 ���۵Ǵ� ��ġ
	OriginalEntryPoint = ImageBase + pNewIOH->AddressOfEntryPoint;
	pNewIOH->AddressOfEntryPoint = MinISH.VirtualAddress + UNPACK_CODE_OFFSET;
	posDecodeSection = BasePointer + MinISH.PointerToRawData + UNPACK_CODE_OFFSET;


	// IDT�� VA�� IDT�� ũ�⸦ ����
	pIID = (PIMAGE_IMPORT_DESCRIPTOR)(Mapped + IDTOffset);
	for (IDTSize = 0; pIID->Name != 0x00000000 && pIID->FirstThunk != 0x00000000; pIID++)
		IDTSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	VirtualAddressIDT = ImageBase + pNewIOH->DataDirectory[0x1].VirtualAddress;


	// IDT�� �����ϰ� �ִ� ������ �����ּҿ�, �� ������ ũ�⸦ ����
	for (Counter = 0; Counter < pFileHeader->NumberOfSections - 1; Counter++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= pNewIOH->DataDirectory[0x1].VirtualAddress && pNewIOH->DataDirectory[0x1].VirtualAddress < (pSectionHeader + 1)->VirtualAddress)
		{
			IDTSection = ImageBase + pSectionHeader->VirtualAddress;
			IDTSectionSize = pSectionHeader->Misc.VirtualSize;
		}
	}

	Counter = 0;
	if (pSectionHeader->VirtualAddress <= pNewIOH->DataDirectory[0x1].VirtualAddress)
		IDTSection = ImageBase + pSectionHeader->VirtualAddress, IDTSectionSize = pSectionHeader->Misc.VirtualSize;


	// KERNEL32.dll�� ��ġ�� LoadLibraryA, VirtualProtect�� IAT
	posKERNEL32 = ImageBase + MinISH.VirtualAddress;
	posLoadLibraryA = ImageBase + MinISH.VirtualAddress + 0xD;
	posGetProcAddress = ImageBase + MinISH.VirtualAddress + 0x11;
	posVirtualProtect = ImageBase + MinISH.VirtualAddress + 0x15;


	// ���� IDT��ġ�� ����� IDT�� ����ִ� .Dong ���� ������ġ�� ����
	posOrgIDT = ImageBase + pNewIOH->DataDirectory[0x1].VirtualAddress;
	posDongIDT = ImageBase + DongISH.VirtualAddress;


	// VirtualProtect()�� 4��° ���� ( 0x8�� �ƹ� �ǹ� ���� )
	GarbageMemory = ImageBase + MinISH.VirtualAddress + MinISH.Misc.VirtualSize - 0x8;


	// ....... KERNEL32.dll �ε��ϰ�, IDT������ PAGE_READWRITE ������ �� .......
	// PUSH KERNERL32.dll
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &posKERNEL32, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posLoadLibrary] 
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH GarbageMemory
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &GarbageMemory, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH 0x04     (PAGE_READWRITE)
	posDecodeSection[Counter++] = 0x68;
	posDecodeSection[Counter++] = 0x04;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// PUSH IDTSize
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH VirtualAddressIDT
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &VirtualAddressIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posVirtualProtect]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posVirtualProtect, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// ...................................................................


	// ....................... IDT�� ���� .......................
	// XOR ECX, ECX
	posDecodeSection[Counter++] = 0x31;		// Opcode
	posDecodeSection[Counter++] = 0xC9;		// ModR/M


	// MOV EBX, IDTSize ( NULL ����ü�� ���� ���� �� �ʿ� ���� )
	posDecodeSection[Counter++] = 0xBB;		// Opcode
	memcpy(&posDecodeSection[Counter], &IDTSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV DL, BYTE PTR DS:[posDongIDT + ECX]
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter;
	posDecodeSection[Counter++] = 0x8A;		// Opcode
	posDecodeSection[Counter++] = 0x91;		// ModR/M
	memcpy(&posDecodeSection[Counter], &posDongIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV BYTE PTR DS:[posOrgIDT + ECX], DL
	posDecodeSection[Counter++] = 0x88;		// Opcode
	posDecodeSection[Counter++] = 0x91;		// ModR/M
	memcpy(&posDecodeSection[Counter], &posOrgIDT, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// CMP ECX, EBX
	posDecodeSection[Counter++] = 0x39;
	posDecodeSection[Counter++] = 0xD9;


	// JNE JumpTo
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0x0F;					// 2 BYTE Opcode
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// .................................................


	// ...................... IAT�� ���� .......................
	// ���� NULL����ü�� ũ��� 0xDE, 0xAD �� ����Ʈ�� ũ�⸦ ����, IAT�� ��ġ��
	posName = ImageBase + DongISH.VirtualAddress + IDTSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(BYTE) * 2;
	posIATRVA = ImageBase + DongISH.VirtualAddress + sizeof(DWORD) * 4;


	// VirtualProtect()�� ����Ͽ� IAT�� �� �� �ֵ��� ��
	// PUSH GarbageMemory
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &GarbageMemory, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH 0x04     (PAGE_READWRITE)
	posDecodeSection[Counter++] = 0x68;
	posDecodeSection[Counter++] = 0x04;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// PUSH IDTSectionSize
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSectionSize, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// PUSH IDTSection
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &IDTSection, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posVirtualProtect]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posVirtualProtect, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// MOV EBX, posIATRVA
	posDecodeSection[Counter++] = 0xBB;
	memcpy(&posDecodeSection[Counter], &posIATRVA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV EDI, ImageBase
	posDecodeSection[Counter++] = 0xBF;
	memcpy(&posDecodeSection[Counter], &ImageBase, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD EDI, [EBX]
	posDecodeSection[Counter++] = 0x03;		// Opcode
	posDecodeSection[Counter++] = 0x3B;		// ModR/M


	// PUSH [posName]
	posDecodeSection[Counter++] = 0x68;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CALL DWORD PTR DS:[posLoadLibraryA]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// XOR ECX, ECX
	posDecodeSection[Counter++] = 0x31;
	posDecodeSection[Counter++] = 0xC9;


	// MOV EDX, EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xC2;


	// CMP BYTE PTR DS:[posName + ECX], 0
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0x00;


	// JNE JumpTo
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0x10A;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// CMP BYTE PTR DS:[posName + ECX], 0xDE
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0xDE;


	// JNE JumpTo
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0xD2;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CMP BYTE PTR DS:[posName + ECX + ESI], 0xAD
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xBC;
	posDecodeSection[Counter++] = 0x0E;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0xAD;


	// JNE JumpTo
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0xD2;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ECX, 2
	posDecodeSection[Counter++] = 0x81;
	posDecodeSection[Counter++] = 0xC1;
	posDecodeSection[Counter++] = 0x02;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// MOV ESI, posName
	posDecodeSection[Counter++] = 0xBE;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ESI, ECX
	posDecodeSection[Counter++] = 0x01;
	posDecodeSection[Counter++] = 0xCE;


	// PUSH ESI
	posDecodeSection[Counter++] = 0x56;


	// MOV ESI, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCE;


	// CALL DWORD PTR DS:[posLoadLibraryA]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posLoadLibraryA, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ECX, ESI
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xF1;


	// ADD EBX, Temp
	Temp = sizeof(DWORD) * 5;
	posDecodeSection[Counter++] = 0x83;
	posDecodeSection[Counter++] = 0xC3;
	memcpy(&posDecodeSection[Counter], &Temp, sizeof(BYTE));
	Counter += sizeof(BYTE);


	// MOV EDI, ImageBase
	posDecodeSection[Counter++] = 0xBF;
	memcpy(&posDecodeSection[Counter], &ImageBase, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD EDI, [EBX]
	posDecodeSection[Counter++] = 0x03;
	posDecodeSection[Counter++] = 0x3B;


	// MOV EDX, EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xC2;


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// JMP JumpTo  ( 1 )
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// CMP BYTE PTR DS:[posName + ECX], 0
	posDecodeSection[Counter++] = 0x80;
	posDecodeSection[Counter++] = 0xB9;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);
	posDecodeSection[Counter++] = 0x00;


	// JNE JumpTo
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0xE4;
	JumpToMedium = JumpToRealCode - 0x6 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0x0F;
	posDecodeSection[Counter++] = 0x85;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// JMP OEP
	JumpToRealCode = OriginalEntryPoint - 0x5 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToRealCode, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV ESI, posName
	posDecodeSection[Counter++] = 0xBE;
	memcpy(&posDecodeSection[Counter], &posName, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// ADD ESI, ECX
	posDecodeSection[Counter++] = 0x01;
	posDecodeSection[Counter++] = 0xCE;

	// PUSH EDX
	posDecodeSection[Counter++] = 0x52;


	// PUSH ESI
	posDecodeSection[Counter++] = 0x56;


	// MOV ESI, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCE;


	// PUSH EDX
	posDecodeSection[Counter++] = 0x52;


	// CALL DWORD PTR DS:[posGetProcAddress]
	posDecodeSection[Counter++] = 0xFF;
	posDecodeSection[Counter++] = 0x15;
	memcpy(&posDecodeSection[Counter], &posGetProcAddress, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// MOV EDX, ECX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xCA;


	// POP EDX
	posDecodeSection[Counter++] = 0x5A;


	// MOV ECX, ESI
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0xF1;


	// MOV DWORD PTR DS:[EDI], EAX
	posDecodeSection[Counter++] = 0x89;
	posDecodeSection[Counter++] = 0x07;


	// ADD EDI, 4
	posDecodeSection[Counter++] = 0x83;
	posDecodeSection[Counter++] = 0xC7;
	posDecodeSection[Counter++] = 0x04;


	// MOV ESI, 1
	posDecodeSection[Counter++] = 0xBE;
	posDecodeSection[Counter++] = 0x01;
	memset(&posDecodeSection[Counter], 0x00, sizeof(BYTE) * 3);
	Counter += sizeof(BYTE) * 3;


	// JMP JumpTo ( 1 )
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);


	// INC ECX
	posDecodeSection[Counter++] = 0x41;


	// JMP JumpTo ( 1 )
	JumpToRealCode = ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + 0x7B;
	JumpToMedium = JumpToRealCode - 0x5 - (ImageBase + MinISH.VirtualAddress + UNPACK_CODE_OFFSET + Counter);
	posDecodeSection[Counter++] = 0xE9;
	memcpy(&posDecodeSection[Counter], &JumpToMedium, sizeof(DWORD));
	Counter += sizeof(DWORD);
	// ..........................................................


	printf("....................... OK !\n");
	return 0;
}

DWORD RVAtoRAW(DWORD RVA)	// RVA ���� RAW�� ��ȯ
{
	PIMAGE_DOS_HEADER			pDOSHeader = (PIMAGE_DOS_HEADER)Mapped;
	PIMAGE_NT_HEADERS			pNTHeader = (PIMAGE_NT_HEADERS)(Mapped + pDOSHeader->e_lfanew);
	PIMAGE_FILE_HEADER			pFileHeader = (PIMAGE_FILE_HEADER)(&pNTHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER		pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)(&pNTHeader->OptionalHeader);
	PIMAGE_SECTION_HEADER		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pOptionalHeader + (pFileHeader->SizeOfOptionalHeader));

	INT Counter;

	if (RVA < pSectionHeader->VirtualAddress)	// �ش� RVA�� ��� ���ǿ��� ���Ե��� �ʴ� ���
		return RVA;

	for (Counter = 0; Counter < pFileHeader->NumberOfSections - 1; Counter++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= RVA && RVA < (pSectionHeader + 1)->VirtualAddress)
			return (RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
	}

	if (pSectionHeader->VirtualAddress <= RVA)	// ������ ���ǿ� �ش� RVA�� ���Ե� ���
		return (RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);

	return -1;
}

DWORD RAWtoRVA(DWORD RAW)	// RAW ���� RVA�� ��ȯ
{
	PIMAGE_DOS_HEADER			pNewIDH = (PIMAGE_DOS_HEADER)BasePointer;
	PIMAGE_NT_HEADERS			pNewINH = (PIMAGE_NT_HEADERS)(BasePointer + pNewIDH->e_lfanew);
	PIMAGE_FILE_HEADER			pNewIFH = (PIMAGE_FILE_HEADER)(&pNewINH->FileHeader);
	PIMAGE_OPTIONAL_HEADER		pNewIOH = (PIMAGE_OPTIONAL_HEADER)(&pNewINH->OptionalHeader);
	PIMAGE_SECTION_HEADER		pNewISH = (PIMAGE_SECTION_HEADER)((LPBYTE)pNewIOH + (pNewIFH->SizeOfOptionalHeader));

	INT Counter;

	for (Counter = 0; Counter < pNewIFH->NumberOfSections - 1; Counter++, pNewISH++)
	{
		if (pNewISH->PointerToRawData <= RAW && RAW < (pNewISH + 1)->PointerToRawData)
			return (RAW + pNewISH->VirtualAddress - pNewISH->PointerToRawData);
	}

	if (pNewISH->PointerToRawData <= RAW)
		return (RAW + pNewISH->VirtualAddress - pNewISH->PointerToRawData);

	return -1;
}

BOOL GetFuncName(HMODULE hMod, WORD Ordinal, PCHAR Name)		// ��⿡�� �Լ��� Ordinal�� �ͽ���Ʈ�Ǵ� ���
{
	LPBYTE LibraryBase = (LPBYTE)hMod;

	LPDWORD AddressOfNamesRVA;
	LPWORD AddressOfNameOrdinalsRVA;

	DWORD NameIndex = 0;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)LibraryBase;
	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(LibraryBase + pIDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pIED;

	pIED = (PIMAGE_EXPORT_DIRECTORY)(LibraryBase + pINH->OptionalHeader.DataDirectory[0x0].VirtualAddress);

	AddressOfNamesRVA = (LPDWORD)(LibraryBase + pIED->AddressOfNames);
	AddressOfNameOrdinalsRVA = (LPWORD)(LibraryBase + pIED->AddressOfNameOrdinals);

	while (1)
	{
		if (AddressOfNameOrdinalsRVA[NameIndex] == Ordinal - pIED->Base)
			break;

		NameIndex++;
	}

	strcpy(Name, (PCHAR)LibraryBase + AddressOfNamesRVA[NameIndex]);
	return 0;
}

BOOL CreatePackedFile(PTCHAR FileName)
{
	PTCHAR pNewFileName, Extension;
	TCHAR NewFileName[MAX_PATH], Ext[6];
	DWORD lpBytesWritten;

	printf("[*] Creating packed file ");

	/*
	pNewFileName = _tcsrchr(FileName, '\\');
	_tcscpy(NewFileName, pNewFileName + 1);		// notepad.exe

	Extension = _tcsrchr(NewFileName, '.');		// .exe
	_tcscpy(Ext, Extension + 1);

	*Extension = '\0\0';						// unicode NULL

	_tcscat(NewFileName, L"_packed");
	_tcscat(NewFileName, L"."); _tcscat(NewFileName, Ext);

	CloseHandle(hFile);
	*/

	_tcscpy(NewFileName, L"packed.exe");
	hFile = CreateFile(NewFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hFile, BasePointer, FileSize + sizeof(IMAGE_SECTION_HEADER) * 2 + DEF_RAWDATA_SIZE1 + DEF_RAWDATA_SIZE2, &lpBytesWritten, NULL);

	CloseHandle(hFile);
	CloseHandle(hMap);

	HeapFree(hHeap, NULL, BasePointer);
	HeapDestroy(hHeap);

	printf(".................. OK !\n");
	return 0;
}