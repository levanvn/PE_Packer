#pragma once
#pragma once
#include <Windows.h>

#pragma pack(push, 1)
void  __stdcall Decrypt(PBYTE data, PBYTE tempheap, DWORD size);
void * __cdecl memcpy1(
	void * dst,
	const void * src,
	unsigned int count
);
void * __cdecl memset1(
	void *dst,
	int val,
	unsigned int count
);


//Structure to store information about packed file
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
#pragma pack(pop)
