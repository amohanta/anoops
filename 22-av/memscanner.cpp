// mem_scan.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "windows.h"
#include <tchar.h>



bool enableDebugPriv()  
{  
	HANDLE hToken;  
	LUID sedebugnameValue;  
	TOKEN_PRIVILEGES tkp;  

	if (!OpenProcessToken(GetCurrentProcess(),   
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {  
			return false;  
	}  
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	tkp.PrivilegeCount = 1;  
	tkp.Privileges[0].Luid = sedebugnameValue;  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	return true;  
}  


int _tmain(int argc, _TCHAR* argv[])
{
	enableDebugPriv() ;
	
	int pid = wcstoul(argv[1], 0, 0);
	HANDLE hProcess=OpenProcess( PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false,pid);
	SYSTEM_INFO sysInfo;
	MEMORY_BASIC_INFORMATION mbi;
	

	int ret;
	//searchstring
	char SeacrhString[32];
	ret = wcstombs ( SeacrhString, argv[2], sizeof(SeacrhString) );
	 //printf("argument string=%s\n",SeacrhString);
	int offset=0;
	BOOL is_match = 0;
	LPVOID searchOffset;
	int foundFlag=0;

	LPVOID memAddr=NULL;
	LPVOID lpBufferX=NULL;
	int vqResult=0;
	HANDLE hFile=NULL;
	 int *  lpBuffer;//A pointer to a buffer that receives the contents from the address space of the specified process.
    	SIZE_T  nSize; //The number of bytes to be read from the specified process.
    	SIZE_T  lpNumberOfBytesRead;
	DWORD dwBytesWritten = 0;
			
         wchar_t MemDumpFileName[16];
			

	GetSystemInfo(&sysInfo);
	ZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));

	while (memAddr < sysInfo.lpMaximumApplicationAddress) 
	{
		      //vqResult=VirtualQueryEx(hProcess,hProcess,memAddr,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
  
	        if(VirtualQueryEx(hProcess,memAddr, &mbi,sizeof(MEMORY_BASIC_INFORMATION)))
			{
				
				//printf("base address=%02x, size_of_region=%02x\n",mbi.BaseAddress,mbi.RegionSize);
					

			//selective blocks
				if(mbi.State==MEM_COMMIT && mbi.RegionSize > 41000)
					{


 
				lpBufferX=VirtualAlloc(NULL,mbi.RegionSize,MEM_COMMIT,PAGE_READWRITE);
				

				 ReadProcessMemory(hProcess, 
						   memAddr,
						   lpBufferX,					
						   (DWORD)mbi.RegionSize,		   
                                                   &lpNumberOfBytesRead);

		  	is_match = -1;
			offset=0;

				 for (offset = 0; offset <  (DWORD)mbi.RegionSize - strlen(SeacrhString);  offset++)
			{
				
				searchOffset=(LPVOID)((CHAR*)lpBufferX + offset); 

				is_match = memcmp(searchOffset, SeacrhString, strlen(SeacrhString));
				if (is_match==0){
					printf("\n\nMatch found in below block:");
					printf("Memory Block = %02x\n", mbi.BaseAddress);
					printf("offset from start of block= %02x\n==========================\n\n", offset);
					
					foundFlag=1;
				swprintf(MemDumpFileName, sizeof(MemDumpFileName) / sizeof(*MemDumpFileName), L"0x%02x", memAddr);//change of name of the file
    //wprintf(L"[%ls]\n", buf2);



				//writing to a file
		hFile = CreateFile(
      MemDumpFileName,     // Filename
      GENERIC_WRITE,          // Desired access
      FILE_SHARE_READ,        // Share mode
      NULL,                   // Security attributes
      CREATE_NEW,             // Creates a new file, only if it doesn't already exist
      FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
      NULL);                  // Template file handle

		

		dwBytesWritten = 0;
		WriteFile( 
                    hFile,           // open file handle
                    lpBufferX,      // start of data to write
                    mbi.RegionSize,  // number of bytes to write
                    &dwBytesWritten, // number of bytes that were written
                    NULL);   

		CloseHandle(hFile);
		
				
					break;
				}

				VirtualFree(lpBufferX,mbi.RegionSize, MEM_RELEASE);
			}
				 //if(foundFlag==1)
					// break;
				

				
				}

		}
	memAddr = (PVOID)( ( (DWORD_PTR)mbi.BaseAddress +(DWORD_PTR)mbi.RegionSize) );	

	}

	return 0;
}

