#pragma once

#include<Windows.h>
#include<stdio.h>
#include<vector>
#include <iostream>
constexpr std::size_t align_up(std::size_t value, std::size_t alignment) noexcept
{
	return (value + alignment - 1) & ~(alignment - 1);
}
struct packed_file_info
{
	DWORD number_of_sections; //Number of original file sections 
	DWORD size_of_packed_data; //Size of packed data
	DWORD size_of_unpacked_data; //Size of original data

	DWORD total_virtual_size_of_sections; //Total virtual size of all original file sections 
	DWORD original_import_directory_rva; //Relative address of original import table
	DWORD original_import_directory_size; //Original import table size
	DWORD original_entry_point; //Original entry point

	DWORD load_library_a; //LoadLibraryA procedure address from kernel32.dll
	DWORD get_proc_address; //GetProcAddress procedure address from kernel32.dll
	DWORD end_of_import_address_table; //IAT end
};

class PEFile {
public:
	DWORD SizeOfVirtualSection = 0;
	DWORD SizeOfAllRawDataSection = 0;
	WORD NumOfSections;
	size_t size_ids{};
	size_t size_dos_stub{};
	size_t size_inh32{};
	size_t size_ish{};
	size_t size_sections{};
	IMAGE_DOS_HEADER ids;
	std::vector<char> MS_DOS_STUB;
	IMAGE_NT_HEADERS32 inh32;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<LPVOID> Sections;
	//void set_sizes(size_t, size_t, size_t, size_t, size_t);
	//PEFile(IMAGE_DOS_HEADER ids, IMAGE_NT_HEADERS32 inh32, std::vector<IMAGE_SECTION_HEADER> ish)
	PEFile(HANDLE handle);
};

PEFile::PEFile(HANDLE handle) {
	HANDLE hFileMap;
	LPVOID lpFile;
	hFileMap = CreateFileMapping(handle, 0, PAGE_READWRITE, 0, 0, 0);
	lpFile = MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	CopyMemory(&ids, lpFile, sizeof(IMAGE_DOS_HEADER));
	DWORD inth = (DWORD)lpFile;
	inth += ids.e_lfanew;

	CopyMemory(&inh32, (void *)inth, sizeof(IMAGE_NT_HEADERS32));
	 NumOfSections = inh32.FileHeader.NumberOfSections;
	 ish = std::vector<IMAGE_SECTION_HEADER>(NumOfSections +1);
	auto FirstSectionHeader = inth + sizeof(IMAGE_NT_HEADERS32);
	for (int i = 0; i < NumOfSections; i++) {
		CopyMemory(&ish[i], (void *)(FirstSectionHeader + i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
		HGLOBAL pRawDataSection = GlobalAlloc(0, ish[i].SizeOfRawData);
		CopyMemory(pRawDataSection, (void *)((DWORD)lpFile + ish[i].PointerToRawData), ish[i].SizeOfRawData);
		Sections.push_back(pRawDataSection);
		SizeOfVirtualSection += align_up(ish[i].Misc.VirtualSize,inh32.OptionalHeader.SectionAlignment);
		SizeOfAllRawDataSection += ish[i].SizeOfRawData;
	}
	UnmapViewOfFile(lpFile);
	CloseHandle(hFileMap);

}