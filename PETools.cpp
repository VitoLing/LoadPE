#include "stdafx.h"
#include "PETools.h"


//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)									
{									
	FILE *pFile = NULL;								
	DWORD fileSize = 0;								
	LPVOID pTempFileBuffer = NULL;								
										
	//打开文件								
	pFile = fopen(lpszFile, "rb");									
	if(!pFile)								
	{								
		printf(" 无法打开 EXE 文件! ");							
		return NULL;							
	}								
	//读取文件大小									
	fseek(pFile, 0, SEEK_END);								
	fileSize = ftell(pFile);									
	fseek(pFile, 0, SEEK_SET);									
	//分配缓冲区								
	pTempFileBuffer = malloc(fileSize);								
									
	if(!pTempFileBuffer)								
	{								
		printf(" 分配空间失败! ");							
		fclose(pFile);							
		return NULL;							
	}								
	//将文件数据读取到缓冲区								
	size_t n = fread(pTempFileBuffer, fileSize, 1, pFile);								
	if(!n)								
	{								
		printf(" 读取数据失败! ");							
		free(pTempFileBuffer);							
		fclose(pFile);							
		return NULL;							
	}								
	//关闭文件								
	*pFileBuffer = pTempFileBuffer;
					
	pTempFileBuffer = NULL;
	fclose(pFile);
	return fileSize;
}									
						
//**************************************************************************								
//RvaToFileOffset:将内存偏移转换为文件偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwRva RVA的值								
//返回值说明：								
//返回转换后的FOA的值  如果失败返回0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer,IN DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;								
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTempImageBuffer = NULL;

	if(pFileBuffer == NULL)
	{
		printf("the pointer to buffer is nosense");
		return 0;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		printf("不是有效的MZ标志\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		printf("不是有效的PE标志\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	//判断dwRva位于节表还是头部
	if( dwRva <= pOptionalHeader->SizeOfHeaders )
		return dwRva;
	// 如果位于头部和第一个节表之间，返回0
	else if((dwRva > pOptionalHeader->SizeOfHeaders) && (dwRva < pSectionHeader->VirtualAddress))
	{
		printf("fuck it\n");
		return 0;
	}
	// 判断dwRva位于哪个节表
	//PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(int i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader++)
	{
		if((dwRva >= (pSectionHeader->VirtualAddress)) && (dwRva <= (pSectionHeader->Misc.VirtualSize + pSectionHeader->VirtualAddress)))
		{
			printf("i = %d\n",i);
		    DWORD offset = dwRva - (pSectionHeader->VirtualAddress);
			return pSectionHeader->PointerToRawData + offset;
		}
	}
	printf("找不到RVA %x 对应的 FOA，转换失败\n",dwRva);
	return 0;
}									

//**************************************************************************								
//Foa2Rva:将文件偏移转换为内存偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwFoa Foa的值								
//返回值说明：								
//返回转换后的RVA的值  如果失败返回0								
//**************************************************************************								
DWORD Foa2Rva(IN LPVOID pFileBuffer,IN DWORD dwFoa)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;								
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTempImageBuffer = NULL;

	if(pFileBuffer == NULL)
	{
		printf("the pointer to buffer is nosense");
		return 0;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		printf("不是有效的MZ标志\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		printf("不是有效的PE标志\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	//判断dwRva位于节表还是头部
	if( dwFoa <= pOptionalHeader->SizeOfHeaders )
		return dwFoa;
	// 判断dwFoa位于哪个节表
	//PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(int i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader++)
	{
		if((dwFoa >= (pSectionHeader->PointerToRawData)) && (dwFoa <= (pSectionHeader->SizeOfRawData + pSectionHeader->PointerToRawData)))
		{
		    DWORD offset = dwFoa - (pSectionHeader->PointerToRawData);
			return pSectionHeader->VirtualAddress + offset;
		}
	}
	printf("找不到Foa %x 对应的Rva，转换失败\n",dwFoa);
	return 0;
}



//**************************************************************************								
//Align:计算对齐后的大小							
//参数说明：								
//x: 没有对齐前的大小，y:按照多少个字节来对齐															
//返回值说明：								
//DWORD 返回x对齐后的大小								
//**************************************************************************
DWORD Align(int x, int y)
{
	// y不能为零
	if(y == 0)
	{
		printf("文件对齐大小不能为零!\n");
		return -1;
	}
	// 计算x / y的商和余数
	int quotient = x/y;
	int remainder = x%y;
	if(remainder == 0)
		return y * quotient;
	else
		return y * (quotient + 1);
}


//**************************************************************************								
//SetPEHeaderInfo:打印导出表信息						
//参数说明：								
//lpszFile：PE文件名称												
//返回值说明：设置成功返回TRUE,失败返回FALSE								
//无返回值							
//**************************************************************************
BOOL SetPEHeaderInfo(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	LPVOID pFileBuffer = NULL;
	DWORD size = 0;
	BOOL isOK = 0;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(!pFileBuffer)
	{
		DbgPrintf("file-->buffer:failure");
		return FALSE;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return FALSE; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return FALSE;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	// 用于存储PE头的信息
	TCHAR szBuffer[128] = {0};
	// 设置入口点地址
	sprintf(szBuffer,"%x",pOptionalHeader->AddressOfEntryPoint);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_EntryPoint,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置镜像基址
	sprintf(szBuffer,"%x",pOptionalHeader->ImageBase);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImageBase,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置镜像大小
	sprintf(szBuffer,"%x",pOptionalHeader->SizeOfImage);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImageSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置代码基址
	sprintf(szBuffer,"%x",pOptionalHeader->BaseOfCode);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BaseOfCode,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置数据基址
	sprintf(szBuffer,"%x",pOptionalHeader->BaseOfData);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BaseOfData,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置内存对齐
	sprintf(szBuffer,"%x",pOptionalHeader->SectionAlignment);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SectionAligent,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置文件对齐
	sprintf(szBuffer,"%x",pOptionalHeader->FileAlignment);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_FileAligent,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置标志字
	sprintf(szBuffer,"%x",pOptionalHeader->LoaderFlags);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_MarkWord,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置子系统
	sprintf(szBuffer,"%x",pOptionalHeader->Subsystem);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SubSystem,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置区段数目
	sprintf(szBuffer,"%x",pPEHeader->NumberOfSections);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_NumberOfSections,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置时间戳
	sprintf(szBuffer,"%x",pPEHeader->TimeDateStamp);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TimeDateStamp,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置PE头大小
	sprintf(szBuffer,"%x",pOptionalHeader->SizeOfHeaders);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SizeOfHeader,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置特征值
	sprintf(szBuffer,"%x",pOptionalHeader->DllCharacteristics);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_Characteristics,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置校验和
	sprintf(szBuffer,"%x",pOptionalHeader->CheckSum);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_CheckSum,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置可选PE头
	sprintf(szBuffer,"%x",pPEHeader->SizeOfOptionalHeader);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_OptionalHeader,WM_SETTEXT,0,(DWORD)szBuffer);
	// 目录项数目
	sprintf(szBuffer,"%x",pOptionalHeader->NumberOfRvaAndSizes);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_NumberOfDirectory,WM_SETTEXT,0,(DWORD)szBuffer);
	return TRUE;
}




//**************************************************************************								
//PrintDirectory:打印导出表信息							
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
VOID PrintDataDirectory(IN LPSTR lpszFile, HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL; 								
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD count = 0; // 用于给sprintf函数计数
	TCHAR PrintBuffer[0xFFFF] = {0}; // 用于输出表中的信息
	LPVOID pFileBuffer = NULL;
	
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return ;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	if(pOptionalHeader->DataDirectory[0].VirtualAddress != 0)
	{
		count = sprintf(PrintBuffer,"FileOffset = %x\r\n",RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[0].VirtualAddress));
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[0].VirtualAddress) + (DWORD)pFileBuffer);
		count += sprintf(PrintBuffer + count, "***********导出表信息*********************\r\n");
		count += sprintf(PrintBuffer + count, "时间戳************************************\r\n");
		count += sprintf(PrintBuffer + count, "TimeDateStamp = %d\r\n",pExportDirectory->TimeDateStamp);
		count += sprintf(PrintBuffer + count, "导出表文件名******************************\r\n");
		count += sprintf(PrintBuffer + count, "Name = %s\r\n",(char*)(RvaToFileOffset(pFileBuffer,pExportDirectory->Name) + (DWORD)pFileBuffer));
		count += sprintf(PrintBuffer + count, "导出函数起始序号**************************\r\n");
		count += sprintf(PrintBuffer + count, "Base = %d\r\n",pExportDirectory->Base);
		count += sprintf(PrintBuffer + count, "所有导出函数的个数************************\r\n");
		count += sprintf(PrintBuffer + count, "NumberOfFunctions = %d\r\n",pExportDirectory->NumberOfFunctions);
		count += sprintf(PrintBuffer + count, "以函数名字导出的函数的个数****************\r\n");
		count += sprintf(PrintBuffer + count, "NumberOfNames = %d\r\n",pExportDirectory->NumberOfNames);
		count += sprintf(PrintBuffer + count, "导出函数地址表****************************\r\n");
		PDWORD AddrOfFuncsInFile = (PDWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions) + (DWORD)pFileBuffer);
		for(DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++,AddrOfFuncsInFile++)
		{
			count += sprintf(PrintBuffer + count,"索引%d:0x%x\r\n",i,*AddrOfFuncsInFile);
		}
		PDWORD AddrOfNamesInFile = (PDWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames) + (DWORD)pFileBuffer);
		for( i = 0; i < pExportDirectory->NumberOfNames; i++, AddrOfNamesInFile++)
		{
			count += sprintf(PrintBuffer + count, "索引%d:%s\r\n",i,(char*)(RvaToFileOffset(pFileBuffer,*AddrOfNamesInFile) + (DWORD)pFileBuffer));
		}
		PWORD AddrOfNameOrdinalsInFile = (PWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals) + (DWORD)pFileBuffer);
		for( i = 0; i < pExportDirectory->NumberOfNames; i++, AddrOfNameOrdinalsInFile++)
		{
			count += sprintf(PrintBuffer + count, "索引%d:%d\r\n",i,*AddrOfNameOrdinalsInFile);
		}
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("设置文本编辑函数执行\n");
	}
	else 
	{
		
		sprintf(PrintBuffer,"这个PE文件没有导出表\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("设置文本编辑函数执行\n");
	}
}

//**************************************************************************								
//PrintRelocation:打印重定位表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
VOID PrintRelocation(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;								
    PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	DWORD count = 0; // 用于给sprintf函数计数
	TCHAR PrintBuffer[0xFFFF] = {0}; // 用于输出表中的信息
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return ;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

	if(pOptionalHeader->DataDirectory[5].VirtualAddress != 0)
	{	
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[5].VirtualAddress) + (DWORD)pFileBuffer);
		while((DWORD)pBaseRelocation != (DWORD)pFileBuffer && pBaseRelocation->VirtualAddress)
		{
			count = sprintf(PrintBuffer,"*********************\r\n");
			count += sprintf(PrintBuffer + count,"%x\r\n",pBaseRelocation->VirtualAddress);
			count += sprintf(PrintBuffer + count,"%x\r\n",(pBaseRelocation->SizeOfBlock - 8)/2);
			// 定义指向页偏移的指针
			PWORD pBlockRva = (PWORD)((DWORD)pBaseRelocation + 8);
			for(DWORD i = 0; i < ((pBaseRelocation->SizeOfBlock - 8) / 2); i++,pBlockRva++)
			{
				count += sprintf(PrintBuffer + count,"第%x项:地址:%x  属性:%x\r\n",i,pBaseRelocation->VirtualAddress+((*pBlockRva)&0x0fff),(*pBlockRva)>>12);
			}
			pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);

		}
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("设置文本编辑函数执行\n");
	}
	else
	{
		sprintf(PrintBuffer,"这个PE文件没有重定位表\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("设置文本编辑函数执行\n");
	}
}



//**************************************************************************								
//PrintImportDescriptor:打印导入表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
BOOL PrintImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	// 在FileBuffer中的位置
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	DWORD count = 0; // 用于给sprintf函数计数
	TCHAR PrintBuffer[0x1FFFF] = {0}; // 用于输出表中的信息
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);


	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return 0;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[1].VirtualAddress) + (DWORD)pFileBuffer);
	// 如果没有遇到结束标志，循环打印导入表信息 
	while(pImportDescriptor->OriginalFirstThunk  != 0)
	{
		// 一个DLL，一个DLL的打印
		// 首先打印DLL的名字
		count = sprintf(PrintBuffer,"*************************************\r\n");
		count += sprintf(PrintBuffer + count,"DLL Name: %s\r\n",(char*)(RvaToFileOffset(pFileBuffer,pImportDescriptor->Name) + (DWORD)pFileBuffer));
		// 接着打印DLL的INT表
		// 定义指向FileBuffer中INT表的指针
		PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(RvaToFileOffset(pFileBuffer,pImportDescriptor->OriginalFirstThunk) + (DWORD)pFileBuffer);
		// 循环打印INT表，结束标志四字节0
		while(pINT->u1.AddressOfData)
		{
			// 首先判断pINT中存的是RVA还是函数导出序号，最高位是否为1
			if((DWORD)pINT->u1.AddressOfData & 0x800000000)
			{
				// 如果是1，直接打印出函数导出序号
				count += sprintf(PrintBuffer +count, "Ordinal Of Function: %x\r\n",pINT->u1.AddressOfData);
				pINT++;
			}
			else
			{
				// 在根据pINT中的RVA找到函数名称，指向另一个结构，先定义一个指针
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer,(DWORD)pINT->u1.AddressOfData) + (DWORD)pFileBuffer);
				// 打印出函数名
				count += sprintf(PrintBuffer + count, " Export Function Name: %s\r\n",(char*)(pImportByName->Name));
				pINT++;
			}
		}
		// 如果是系统程序，PE加载前IAT和INT可能不同，这里默认是相同的，默认不知道绑定导入表
		// 定义指向FileBuffer中IAT表的指针
		PIMAGE_THUNK_DATA32 pIAT = (PIMAGE_THUNK_DATA32)(RvaToFileOffset(pFileBuffer,pImportDescriptor->FirstThunk) + (DWORD)pFileBuffer);
		// 循环打印IAT表，结束标志四字节0
		while(pIAT->u1.AddressOfData)
		{
			// 首先判断pIAT中存的是RVA还是函数导出序号，最高位是否为1
			if((DWORD)pIAT->u1.AddressOfData & 0x800000000)
			{
				// 如果是1，直接打印出函数导出序号
				count += sprintf(PrintBuffer + count,"Ordinal Of Function: %x\r\n",pIAT->u1.AddressOfData);
				pIAT++;
			}
			else
			{
				// 在根据pINT中的RVA找到函数名称，指向另一个结构，先定义一个指针
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer,(DWORD)pIAT->u1.AddressOfData) + (DWORD)pFileBuffer);
				// 打印出函数名
				count += sprintf(PrintBuffer + count, " Export Function Name: %s\r\n",(char*)(pImportByName->Name));
				pIAT++;
			}
		}
		pImportDescriptor++;
	}
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
	return 1;
}

//**************************************************************************								
//PrintBoundImportDescriptor:打印绑定导入表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//打印成功返回1，失败返回0							
//**************************************************************************
BOOL PrintBoundImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	// 在FileBuffer中的位置,绑定导入表指针
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;
	// 在ImageBuffer中的位置，用于计算函数名称RVA
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptorInImageBuffer = NULL;
	DWORD count = 0; // 用于给sprintf函数计数
	TCHAR PrintBuffer[0xFFFF] = {0}; // 用于输出表中的信息
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);

	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return 0;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	// 数据目录项中的第12项
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[11].VirtualAddress) + (DWORD)pFileBuffer);
	pBoundImportDescriptorInImageBuffer = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(pOptionalHeader->DataDirectory[11].VirtualAddress);
	// 如果没有绑定导入表
	if (pBoundImportDescriptor == NULL)
	{
		sprintf(PrintBuffer,"这个PE文件没有绑定导入表\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		return 0;
	}
	// 如果没有遇到结束标志，循环打印绑定导入表信息
	count = sprintf(PrintBuffer,"**********************************\r\n");
	while(pBoundImportDescriptor->TimeDateStamp + pBoundImportDescriptor->OffsetModuleName + pBoundImportDescriptor->NumberOfModuleForwarderRefs)
	{
		count += sprintf(PrintBuffer + count,"**********************************\r\n");
		// 首先打印整个DLL的名称
		count += sprintf(PrintBuffer + count,"dll名称：%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
		DbgPrintf("dll名称：%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
		if(pBoundImportDescriptor->NumberOfModuleForwarderRefs)
		{
			// 再打印IMAGE_BOUND_FORWARDER_REF中的OffsetModulez指向的函数名
			for(DWORD i = 0; i < pBoundImportDescriptor->NumberOfModuleForwarderRefs; i++,pBoundImportDescriptor++)
			{
				count += sprintf(PrintBuffer + count,"导入函数名：%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
			}
		//	pBoundImportDescriptorInImageBuffer+=(i+1);
		}
		else
		{
			pBoundImportDescriptor++;
		}
	}
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
	return 1;
}


//**************************************************************************								
//PrintResourceTable:打印资源表信息						
//参数说明：								
//FileBuffer，pResDir 资源表入口， RootAddress 根目录起始位置											
//返回值说明：								
//无返回值							
//**************************************************************************
BOOL PrintResourceTable(LPVOID pFileBuffer,PIMAGE_RESOURCE_DIRECTORY  pResDir,DWORD RootAddress,HWND hwndDlg)
{	
	if (pFileBuffer == NULL)
	{
		DbgPrintf("文件加载异常\n");
		return 0;
	}
	if (pResDir == NULL)
	{
		DbgPrintf("资源表指针异常\n");
		return FALSE;
	}
	DWORD SumOfItems = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);
	DWORD count = 1;
	DWORD index = 0; // 用于修改PrintBuffer指针
	char PrintBuffer[0xffff] = {0}; // 用于存放打印信息
	while (count <= SumOfItems)
	{
		if(pResDirEntry->NameIsString)
		{
			PIMAGE_RESOURCE_DIR_STRING_U pResDirStr_U = (PIMAGE_RESOURCE_DIR_STRING_U)(pResDirEntry->NameOffset + RootAddress);
			index += sprintf(PrintBuffer + index,"资源编号：%s\r\n",pResDirStr_U->NameString);
		}
		else
		{
			index += sprintf(PrintBuffer + index,"资源编号：%x\r\n",pResDirEntry->Id);
		}
		if (pResDirEntry->DataIsDirectory)
		{
			PrintResourceTable(pFileBuffer,(PIMAGE_RESOURCE_DIRECTORY)((RootAddress + pResDirEntry->OffsetToDirectory)),RootAddress,hwndDlg);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY pResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(RootAddress+pResDirEntry->OffsetToDirectory);
			index += sprintf(PrintBuffer + index,"RVA:%x\r\n",pResDataEntry->OffsetToData);
			index += sprintf(PrintBuffer + index,"Size:%x\r\n",pResDataEntry->Size);
		}
		count++;
		pResDirEntry++;
	}
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
	return TRUE;
}


//**************************************************************************								
//EnumSections: 遍历节表，将信息输出到ListView						
//参数说明：								
//hwndDlg:窗口句柄，filename：PE文件名称															
//返回值说明：								
//无返回值			
//**************************************************************************
BOOL EnumSections(IN LPSTR lpszFile,HWND hListModule)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;								
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pFileBuffer = NULL;
	LV_ITEM lv;
	TCHAR buffer[0x20]; // 用于存储节表中的各种信息转化的字符串
	//初始化
	memset(&lv,0,sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;

	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(!pFileBuffer)
	{
		DbgPrintf("file-->buffer:failure");
		return FALSE ;
	}								
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return FALSE; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return FALSE;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	for (DWORD i = 0 ;  i < pPEHeader->NumberOfSections; i++)
	{
	
		// 设置节名
		DbgPrintf("Section Name: %s\n",TEXT(pSectionHeader->Name));
		lv.pszText =TEXT((char*)pSectionHeader->Name);
		lv.iItem = i;
		lv.iSubItem = 0;
		ListView_InsertItem(hListModule,&lv);
		// 设置文件偏移
		sprintf(buffer,"%x",pSectionHeader->PointerToRawData);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 1;
		ListView_SetItem(hListModule,&lv);
		// 设置此节在文件中的大小
		sprintf(buffer,"%x",pSectionHeader->SizeOfRawData);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 2;
		ListView_SetItem(hListModule,&lv);
		// 设置内存偏移
		sprintf(buffer,"%x",pSectionHeader->VirtualAddress);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 3;
		ListView_SetItem(hListModule,&lv);
		// 设置内存大小
		sprintf(buffer,"%x",pSectionHeader->Misc.VirtualSize);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 4;
		ListView_SetItem(hListModule,&lv);
		// 设置节的属性
		sprintf(buffer,"%x",pSectionHeader->Characteristics);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 5;
		ListView_SetItem(hListModule,&lv);
		pSectionHeader+=1;
	}
	return TRUE;
}

//**************************************************************************								
//EnumDataDirectory: 遍历数据目录项，将信息输出到ListView						
//参数说明：								
//hwndDlg:窗口句柄，filename：PE文件名称															
//返回值说明：								
//无返回值			
//**************************************************************************
VOID EnumDataDirectory(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;	
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;		
	LPVOID pFileBuffer = NULL;

	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(!pFileBuffer)
	{
		DbgPrintf("file-->buffer:failure");
		return  ;
	}								
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

	// 用于存放每个数据项的Rva和Size的字符串
	TCHAR szBuffer[0x20] = {0};

	// 设置导出表的Rva和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[0].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[0].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置导入表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[1].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[1].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置资源表的RVA和Siz
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[2].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ResourceRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[2].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ResourceSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置异常表的RVa和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[3].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExceptionRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[3].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExceptionSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置安全表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[4].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SafeRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[4].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SafeSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置重定位表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[5].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_RelocationRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[5].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_RelocationSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置调试表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[6].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DebugRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[6].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DebugSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置版权表的RVA和Siz
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[7].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_AuthorityRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[7].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_AuthoritySize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置全局指针表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[8].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_GlobalPointerRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[8].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_GlobalPointerSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置Tls的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[9].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[9].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置导入配置表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[10].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_LoadConfRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[10].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_LoadConfSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置绑定导入表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[11].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BoundImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[11].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BoundImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置IAT表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[12].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[12].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置延迟导入表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[13].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DelayImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[13].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DelayImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置COM表的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[14].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[14].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// 设置保留字段的RVA和Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[15].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ReservedRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[15].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ReservedSize,WM_SETTEXT,0,(DWORD)szBuffer);

}



//TES Function: print Resource table
VOID TestPrintResourceDir(IN LPSTR lpszFile,HWND hwndDlg)
{
	LPVOID pFileBuffer = NULL;
	//LPVOID pImageBuffer = NULL;
	BOOL isOK = 0;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(!pFileBuffer)
	{
		DbgPrintf("file-->buffer:failure");
		return ;
	}
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	// 在FileBuffer中的位置
    PIMAGE_RESOURCE_DIRECTORY  pResourceDir_first = NULL;
	
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense\n");
		return ;
	}
	//判断是否是有效的MZ标志								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("不是有效的MZ标志\n");							
		return ; 							
	}	

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("不是有效的PE标志\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pResourceDir_first = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[2].VirtualAddress) + (DWORD)pFileBuffer);
	PrintResourceTable(pFileBuffer,pResourceDir_first,(DWORD)pResourceDir_first,hwndDlg);
}
