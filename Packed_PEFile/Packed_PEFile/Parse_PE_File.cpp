
#include<ParsePE.h>
#include<Windows.h>
#include<stdio.h>
#include<vector>
#include <iostream>
#include<string>
#include <Unpacker.h>
#include<fstream>
LPVOID   Decrypt(PBYTE data, DWORD size) {

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
	int it, j;
	BYTE temp[32];
	it = 0;
	for (j = 0; j < sizeof(buf); j++) {
		temp[j] = *(data + it);
		*(data + it) = *(data + it) ^ buf[j];
		it++;
	}

 	while (it < size) {

		// temp = *(data+it- sizeof(buf)) ^ 
		for (j = 0; j < sizeof(buf); j++) {
			// temp = *(data + it - sizeof(buf)) ^ buf[j];
			*(data + it) = *(data + it) ^ temp[j];
			temp[j] ^= *(data + it);
 			it++;
			
		}
	}
	return 0;
}
LPVOID Encrypt(PBYTE data, DWORD size) {
	LPVOID ret = (LPVOID)data;
	BYTE a[] = { 84,114,117,111,110,103,75,104,97,110,104,76,105, 110, 104, 45 ,45, 80, 104 ,
		97,109,84,104,105,66,105,99,104,84,104,97,111};
	int it = 0;
	while (it < sizeof(a)) {
		*(data + it) ^= a[it];
		it++;
	}
	while(it < size){

			*(data + it) ^= *(data + it - sizeof(a));
			it++;
	}
	
	return ret;
}

int main(int argc, char* argv[]) {
	if (argc != 3 )
	{
		std::cout << "Usage: simple_pe_packer.exe PE_FILE" << std::endl;
		return 0;
	}
	std::cout << "Reading PE File....\n";

	HANDLE hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	PEFile pefile(hFile);
	CloseHandle(hFile);
	packed_file_info basic_info;
	basic_info.number_of_sections = pefile.NumOfSections;
	basic_info.original_entry_point = pefile.inh32.OptionalHeader.AddressOfEntryPoint;
	basic_info.original_import_directory_rva = pefile.inh32.OptionalHeader.DataDirectory[1].VirtualAddress;
	basic_info.original_import_directory_size = pefile.inh32.OptionalHeader.DataDirectory[1].Size;
	basic_info.total_virtual_size_of_sections = pefile.SizeOfVirtualSection;
	

	DWORD sizeOfDataPacked = pefile.NumOfSections * sizeof(IMAGE_SECTION_HEADER) + pefile.SizeOfAllRawDataSection;
	if (sizeOfDataPacked % 32 != 0) { sizeOfDataPacked += sizeOfDataPacked % 32; }

	basic_info.size_of_packed_data = sizeOfDataPacked;

	DWORD SpaceForImport = 2 * 20 + 10 + 64;

	DWORD sizeOfRaw = sizeof(packed_file_info) + sizeOfDataPacked + SpaceForImport;

	HGLOBAL  packed_sections_info = GlobalAlloc(0, sizeOfRaw);
	memset(packed_sections_info, 0, sizeOfRaw);
	// Copy Section Header........................

	
	DWORD pSecHec = (DWORD) packed_sections_info + sizeof(packed_file_info);
	for (int i = 0; i < pefile.NumOfSections; i++) {

		CopyMemory((LPVOID)pSecHec, &pefile.ish[i], sizeof(IMAGE_SECTION_HEADER));
		pSecHec = pSecHec + sizeof(IMAGE_SECTION_HEADER);
	}

	// Copy Section Raw Data..........................

	DWORD pPacked = (DWORD)packed_sections_info + pefile.NumOfSections * sizeof(IMAGE_SECTION_HEADER) + sizeof(basic_info);
	
	for (int i = 0; i < pefile.NumOfSections; i++) {

		CopyMemory((LPVOID)pPacked, pefile.Sections[i],pefile.ish[i].SizeOfRawData);
		pPacked = pPacked+ pefile.ish[i].SizeOfRawData;
		VirtualFree(pefile.Sections[i], pefile.ish[i].SizeOfRawData, MEM_RELEASE);
	}

	// Encode orginal section header + all raw data
	std::cout << "Encrypting data....\n";

	LPVOID data = Encrypt((PBYTE)packed_sections_info+ sizeof(basic_info), sizeOfDataPacked);
	//data = Decrypt((PBYTE)data, sizeOfDataPacked);
	std::cout << "Encrypting complete...\n";


	// Calculate new Section Header for Packed file
	//Section Header 1
	IMAGE_SECTION_HEADER ish;
	const char name[] = "packed";
	memset(&ish,0,sizeof(ish));
	memcpy(&ish.Name, name, sizeof(name));
	ish.Misc.VirtualSize = pefile.SizeOfVirtualSection;
	ish.SizeOfRawData = align_up(sizeOfRaw, pefile.inh32.OptionalHeader.FileAlignment);
	ish.PointerToRawData = align_up(sizeof(pefile.ids)+sizeof(pefile.inh32)+2*sizeof(IMAGE_SECTION_HEADER), pefile.inh32.OptionalHeader.FileAlignment);
	ish.VirtualAddress = pefile.ish[0].VirtualAddress;
	ish.Characteristics = 0xE0000000;

	pefile.ish.clear();
	pefile.ish.push_back(ish);
	pefile.inh32.FileHeader.NumberOfSections = 2;

	// Import Decription in Section 1 Raw Data
	std::cout << "Creating Import...\n";
	DWORD RVA_Of_ImportDirectory = ish.VirtualAddress + sizeof(packed_file_info) + sizeOfDataPacked;
	pefile.inh32.OptionalHeader.DataDirectory[1].VirtualAddress = RVA_Of_ImportDirectory;

	DWORD pImport = (DWORD)packed_sections_info + sizeof(basic_info) + sizeOfDataPacked;
	PIMAGE_IMPORT_DESCRIPTOR pImDe = (PIMAGE_IMPORT_DESCRIPTOR) pImport;

	pImDe->FirstThunk = pefile.ish[0].VirtualAddress + offsetof(packed_file_info, load_library_a);
	pImport += 2*sizeof(IMAGE_IMPORT_DESCRIPTOR);
	const char kernell32[] = "kernel32.dll";
	const char LoadLibraryA[] = "  LoadLibraryA";
	const char GetProcAdrress[] = "  GetProcAddress"; 

	memcpy((LPVOID)pImport, kernell32, sizeof(kernell32));
	DWORD RvaOfKernel = pImport - (DWORD)packed_sections_info+ pefile.ish[0].VirtualAddress;
	pImDe->Name = RvaOfKernel;
	pImport += sizeof(kernell32);

	memcpy((LPVOID)pImport, LoadLibraryA, sizeof(LoadLibraryA));
	basic_info.load_library_a = pImport - (DWORD)packed_sections_info + pefile.ish[0].VirtualAddress;

	pImport += sizeof(LoadLibraryA);
	memcpy((LPVOID)pImport, GetProcAdrress, sizeof(GetProcAdrress));
	basic_info.get_proc_address = pImport - (DWORD)packed_sections_info + pefile.ish[0].VirtualAddress;
	basic_info.end_of_import_address_table = 0;
	CopyMemory(packed_sections_info, &basic_info, sizeof(basic_info));

	std::cout << "Creating Import Complete...\n";

	// Section header 2- unpacked stub
	IMAGE_SECTION_HEADER ish1;
	const char name1[] = "unpacked";
	memset(&ish1, 0, sizeof(ish1));
	memcpy(&ish1.Name, name1, sizeof(name1));	
	ish1.PointerToRawData = pefile.ish[0].PointerToRawData + pefile.ish[0].SizeOfRawData;
	
	ish1.VirtualAddress = align_up(pefile.ish[0].VirtualAddress + pefile.ish[0].Misc.VirtualSize, pefile.inh32.OptionalHeader.SectionAlignment);
	ish1.Characteristics = 0xE0000000;
	ish1.SizeOfRawData = sizeof(unpacker_data);
	ish1.Misc.VirtualSize = sizeof(unpacker_data);

	//CreateFile(argv[2], GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0); 

	// Raw data for unpacked stub
	char * unpacked_raw_data;
	unpacked_raw_data  = new char (sizeof(unpacker_data));
	CopyMemory(unpacked_raw_data, &unpacker_data, sizeof(unpacker_data));
	CopyMemory(&unpacked_raw_data[original_image_base_offset],&pefile.inh32.OptionalHeader.ImageBase,sizeof(DWORD));
	CopyMemory(&unpacked_raw_data[rva_of_first_section_offset],& pefile.ish[0].VirtualAddress,sizeof(DWORD));

	pefile.ish.push_back(ish1);

	// Create new file packed
	//CopyMemory((LPVOID)((DWORD)packed_sections_info + sizeof(basic_info)), &pefile.ish[0], sizeof(pefile.ish));
	pefile.ids.e_lfanew = sizeof(pefile.ids);
	pefile.inh32.OptionalHeader.AddressOfEntryPoint = pefile.ish[1].VirtualAddress;
	pefile.inh32.OptionalHeader.SizeOfImage = pefile.ish[1].VirtualAddress + pefile.ish[1].SizeOfRawData;

	DWORD size_new_file = pefile.ish[1].PointerToRawData + pefile.ish[1].SizeOfRawData;
	HGLOBAL r_ch = GlobalAlloc(0,size_new_file+1) ;
	CopyMemory(r_ch,&pefile.ids, sizeof(pefile.ids));
	CopyMemory((LPVOID) ((DWORD)r_ch + sizeof(pefile.ids)), &pefile.inh32, sizeof(pefile.inh32));
	CopyMemory( (LPVOID) ( (DWORD)r_ch + sizeof(pefile.ids) + sizeof(pefile.inh32)), &pefile.ish[0], 2*sizeof(pefile.ish[0]));
	CopyMemory((LPVOID) ((DWORD)r_ch +  pefile.ish[0].PointerToRawData), packed_sections_info, sizeOfRaw);
	CopyMemory((LPVOID)((DWORD)r_ch + pefile.ish[1].PointerToRawData), unpacked_raw_data,sizeof(unpacker_data));
	
	VirtualFree(packed_sections_info, sizeof(sizeOfRaw), MEM_RELEASE);
	VirtualFree(unpacked_raw_data, sizeof(unpacker_data), MEM_RELEASE);
	//auto outfile = std::experimental::filesystem::path{ argv[2] }.generic_string();
	DWORD num=0;
	num += 2; 
	HANDLE hOut = CreateFile(argv[2], GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,0);
	if (NULL == hFile)
	{
		printf("failed - %d", GetLastError());
	}
	WriteFile(hOut, r_ch, size_new_file, &num, 0);

	

}