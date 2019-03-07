#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
//PE library header file 

using namespace std;

int main(int argc, char* argv[])
{
	//Usage hints
	if(argc != 3)
	{
		std::cout << "Usage: unpacker_converter.exe unpacker.exe output.h" << std::endl;
		return 0;
	}

	//Open unpacker.exe file - its name
	//and path are stored in argv array at index 1
	std::fstream file(argv[1], std::ios::in);
	std::fstream outfile(argv[2], std::ios::out);
	if(!file)
	{
		//If file open failed - display message and exit with an error
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}
	
	 int  begin,end;
	 int size;
	 begin = file.tellg();
	 cout << begin;
  file.seekg (0, ios::end);
  size  = file.tellg();
	  file.seekg(0, ios::beg);
	 begin = file.tellg();
	 
	 char a = ',',b;
	 int i = begin;
	 cout << size << endl;
	 while(!file.eof() ){
		 //cout << i << " ";
		//file.seekg(i,ios::cur);
		outfile << "0x";
		file >> b;
		cout << b;
		outfile << b;
		file >> b;
		cout << b;
		outfile << b;
		outfile << ',';
		i = i + 1;
		if (i%17==0) outfile << endl;
	 }
	
	file.close();
	return 0;
}