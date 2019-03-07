#include<Header.h>


extern "C" void __declspec(naked) unpacker_main()
{
	//Create prologue manually
	__asm
	{
		push ebp;
		mov ebp, esp;
		sub esp, 256;
	}
	DWORD original_image_base;
	DWORD rva_of_first_section;
	__asm
	{
		mov original_image_base, 0x11111111;
		mov rva_of_first_section, 0x22222222;
	}
	 packed_file_info* info;
	//It is stored in the beginning
	//of packed file first section
	info = reinterpret_cast< packed_file_info*>(original_image_base + rva_of_first_section);

	//Two LoadLibraryA and GetProcAddress function prototypes typedefs 
	typedef HMODULE(__stdcall* load_library_a_func)(const char* library_name);
	typedef INT_PTR(__stdcall* get_proc_address_func)(HMODULE dll, const char* func_name);

	//Read their addresses from packed_file_info structure
	//Loader puts them there for us
	load_library_a_func load_library_a;
	get_proc_address_func get_proc_address;
	load_library_a = reinterpret_cast<load_library_a_func>(info->load_library_a);
	get_proc_address = reinterpret_cast<get_proc_address_func>(info->get_proc_address);


	//Create buffer on stack
	char buf[32];
	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'nrek';
	*reinterpret_cast<DWORD*>(&buf[4]) = '23le';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'lld.';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Load kernel32.dll library
	HMODULE kernel32_dll;
	kernel32_dll = load_library_a(buf);

	//VirtualAlloc function prototype typedef
	typedef LPVOID(__stdcall* virtual_alloc_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
	//VirtualProtect function prototype typedef
	typedef LPVOID(__stdcall* virtual_protect_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	//VirtualFree function prototype typedef
	typedef LPVOID(__stdcall* virtual_free_func)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);

	//VirtualAlloc
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Alau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'coll';
	*reinterpret_cast<DWORD*>(&buf[12]) = 0;

	//Get VirtualAlloc function address
	virtual_alloc_func virtual_alloc;
	virtual_alloc = reinterpret_cast<virtual_alloc_func>(get_proc_address(kernel32_dll, buf));

	//VirtualProtect
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Plau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'etor';
	*reinterpret_cast<DWORD*>(&buf[12]) = 'tc';

	//Get VirtualProtect function address
	virtual_protect_func virtual_protect;
	virtual_protect = reinterpret_cast<virtual_protect_func>(get_proc_address(kernel32_dll, buf));

	//VirtualFree
	*reinterpret_cast<DWORD*>(&buf[0]) = 'triV';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'Flau';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'eer';

	//Get VirtualFree function address
	virtual_free_func virtual_free;
	virtual_free = reinterpret_cast<virtual_free_func>(get_proc_address(kernel32_dll, buf));

	//Relative virtual address of import directory
	DWORD original_import_directory_rva;
	//Import directory virtual address
	DWORD original_import_directory_size;
	//Original entry point
	DWORD original_entry_point;
	//Total size of all file sections
	DWORD total_virtual_size_of_sections;
	//Number of original file sections
	DWORD number_of_sections;
	DWORD size_unpacked;
	//Copy these values from packed_file_info structure,
	//which was saved for us by the packer
	original_import_directory_rva = info->original_import_directory_rva;
	original_import_directory_size = info->original_import_directory_size;
	original_entry_point = info->original_entry_point;
	total_virtual_size_of_sections = info->total_virtual_size_of_sections;
	number_of_sections = info->number_of_sections;
	size_unpacked = info->size_of_packed_data;

	 
	//Pointer to the memory 
	//to store unpacked data
	LPVOID unpacked_mem;
	//Allocate the memory
	unpacked_mem = virtual_alloc(
		0,
		info->size_of_unpacked_data,
		MEM_COMMIT,
		PAGE_READWRITE);
	//char buf1[32];
	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'ourT';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'hKgn';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'Lhna';
	*reinterpret_cast<DWORD*>(&buf[12]) = '-hni';
	*reinterpret_cast<DWORD*>(&buf[16]) = 'ahP-';
	*reinterpret_cast<DWORD*>(&buf[20]) = 'ihTm';
	*reinterpret_cast<DWORD*>(&buf[24]) = 'hciB';
	*reinterpret_cast<DWORD*>(&buf[28]) = 'oahT';
	int it, j;
	it = 0;
	LPVOID pInfo;
	BYTE temp[32];
	pInfo = (LPVOID)info;
	pInfo = (LPVOID) ((DWORD)pInfo+sizeof(packed_file_info));
	//(DWORD)info = (DWORD)((DWORD) info+sizeof(packed_file_info));
	for (j = 0; j < sizeof(buf); j++) {
		//temp[j] = *(data + it);
		*((PBYTE)unpacked_mem + it) = *((PBYTE)pInfo + it) ^ buf[j];
		it++;
	}
	while (it < size_unpacked) {

		for (j = 0; j < sizeof(buf); j++) {
			*((PBYTE)unpacked_mem + it) = *((PBYTE)pInfo + it) ^ *((PBYTE)pInfo + it - 32);
			it++;
		}
	}
	 // Decrypt((PBYTE)info + sizeof(packed_file_info),(PBYTE) unpacked_mem, info->size_of_packed_data);

	  memset1((void *)info, 0, total_virtual_size_of_sections);

	  PIMAGE_SECTION_HEADER orginal_section_header;
	  orginal_section_header = (PIMAGE_SECTION_HEADER)unpacked_mem;
	 
	  DWORD back_size; back_size  = 0;
	  for (int i = 0; i < number_of_sections; i++) {
		  memcpy1((void *)(original_image_base + orginal_section_header->VirtualAddress), (LPVOID) ((DWORD)unpacked_mem+ number_of_sections*sizeof(IMAGE_SECTION_HEADER)+ back_size), orginal_section_header->SizeOfRawData);
		  
		  back_size += orginal_section_header->SizeOfRawData;
		  orginal_section_header += 1;
	  }
	  virtual_free(unpacked_mem, size_unpacked, MEM_RELEASE);

	  //Fill IAT 
	  DWORD offset_to_orginal_directories;
	  offset_to_orginal_directories = original_image_base + original_import_directory_rva;

	  //Pointer to import directory
	  
	  if (original_import_directory_rva)
	  {
		  //First descriptor virtual address
		  IMAGE_IMPORT_DESCRIPTOR* descr;
		  descr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(original_import_directory_rva + original_image_base);

		  //List all descriptors
		  //Last one is nulled
		  while (descr->Name)
		  {
			  //Load the required DLL
			  HMODULE dll;
			  dll = load_library_a(reinterpret_cast<char*>(descr->Name + original_image_base));
			  //Pointers to address table and lookup table
			  DWORD* lookup, *address;
			  //Take into account that lookup table may be absent,
			  //as I mentioned at previous step
			  lookup = reinterpret_cast<DWORD*>(original_image_base + (descr->OriginalFirstThunk ? descr->OriginalFirstThunk : descr->FirstThunk));
			  address = reinterpret_cast<DWORD*>(descr->FirstThunk + original_image_base);

			  //List all descriptor imports
			  while (true)
			  {
				  //Till the first null element in lookup table
				  DWORD lookup_value = *lookup;
				  if (!lookup_value)
					  break;

				  //Check if the function is imported by ordinal
				  if (IMAGE_SNAP_BY_ORDINAL32(lookup_value))
					  *address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value & ~IMAGE_ORDINAL_FLAG32)));
				  else
					  *address = static_cast<DWORD>(get_proc_address(dll, reinterpret_cast<const char*>(lookup_value + original_image_base + sizeof(WORD))));

				  //Move to next element
				  ++lookup;
				  ++address;
			  }

			  //Move to next descriptor
			  ++descr;
		  }
	  }
	_asm
	{
		//Move to original entry point
		mov eax, original_entry_point;
		add eax, original_image_base;
		leave;
		//Like this
		jmp eax;
	}
}
/*
void  __stdcall Decrypt(PBYTE data, PBYTE tempheap, DWORD size) {

	char buf[32];
	//kernel32.dll
	*reinterpret_cast<DWORD*>(&buf[0]) = 'ourT';
	*reinterpret_cast<DWORD*>(&buf[4]) = 'hKgn';
	*reinterpret_cast<DWORD*>(&buf[8]) = 'Lhna';
	*reinterpret_cast<DWORD*>(&buf[12]) = '-hni';
	*reinterpret_cast<DWORD*>(&buf[16]) = 'ahP-';
	*reinterpret_cast<DWORD*>(&buf[20]) = 'ihTm';
	*reinterpret_cast<DWORD*>(&buf[24]) = 'hciB';
	*reinterpret_cast<DWORD*>(&buf[28]) = 'oahT';
	int it,j;
	it = 0;
	for ( j = 0; j < sizeof(buf); j++) {
		*(tempheap + it) = *(data + it) ^ buf[j];
		it++;
	}
	while (it < size) {

		for ( j = 0; j < sizeof(buf); j++) {
			*(tempheap + it) = *(data + it) ^ *(data + it - 32);
			it++;
		}
	}
	
}
*/
void * __cdecl memset1(
	void *dst,
	int val,
	unsigned int count
)
{
	void *start = dst;

	while (count--) {
		*(char *)dst = (char)val;
		dst = (char *)dst + 1;
	}

	return(start);
}

void * __cdecl memcpy1(
	void * dst,
	const void * src,
	unsigned int count
)
{
	void * ret = dst;

	/*
	 * copy from lower addresses to higher addresses
	 */
	while (count--) {
		*(char *)dst = *(char *)src;
		dst = (char *)dst + 1;
		src = (char *)src + 1;
	}

	return(ret);
}
