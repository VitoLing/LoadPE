#include "stdafx.h"
#include "PETools.h"


//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer)									
{									
	FILE *pFile = NULL;								
	DWORD fileSize = 0;								
	LPVOID pTempFileBuffer = NULL;								
										
	//���ļ�								
	pFile = fopen(lpszFile, "rb");									
	if(!pFile)								
	{								
		printf(" �޷��� EXE �ļ�! ");							
		return NULL;							
	}								
	//��ȡ�ļ���С									
	fseek(pFile, 0, SEEK_END);								
	fileSize = ftell(pFile);									
	fseek(pFile, 0, SEEK_SET);									
	//���仺����								
	pTempFileBuffer = malloc(fileSize);								
									
	if(!pTempFileBuffer)								
	{								
		printf(" ����ռ�ʧ��! ");							
		fclose(pFile);							
		return NULL;							
	}								
	//���ļ����ݶ�ȡ��������								
	size_t n = fread(pTempFileBuffer, fileSize, 1, pFile);								
	if(!n)								
	{								
		printf(" ��ȡ����ʧ��! ");							
		free(pTempFileBuffer);							
		fclose(pFile);							
		return NULL;							
	}								
	//�ر��ļ�								
	*pFileBuffer = pTempFileBuffer;
					
	pTempFileBuffer = NULL;
	fclose(pFile);
	return fileSize;
}									
						
//**************************************************************************								
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwRva RVA��ֵ								
//����ֵ˵����								
//����ת�����FOA��ֵ  ���ʧ�ܷ���0								
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
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		printf("������Ч��MZ��־\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		printf("������Ч��PE��־\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	//�ж�dwRvaλ�ڽڱ���ͷ��
	if( dwRva <= pOptionalHeader->SizeOfHeaders )
		return dwRva;
	// ���λ��ͷ���͵�һ���ڱ�֮�䣬����0
	else if((dwRva > pOptionalHeader->SizeOfHeaders) && (dwRva < pSectionHeader->VirtualAddress))
	{
		printf("fuck it\n");
		return 0;
	}
	// �ж�dwRvaλ���ĸ��ڱ�
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
	printf("�Ҳ���RVA %x ��Ӧ�� FOA��ת��ʧ��\n",dwRva);
	return 0;
}									

//**************************************************************************								
//Foa2Rva:���ļ�ƫ��ת��Ϊ�ڴ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwFoa Foa��ֵ								
//����ֵ˵����								
//����ת�����RVA��ֵ  ���ʧ�ܷ���0								
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
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		printf("������Ч��MZ��־\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		printf("������Ч��PE��־\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	//�ж�dwRvaλ�ڽڱ���ͷ��
	if( dwFoa <= pOptionalHeader->SizeOfHeaders )
		return dwFoa;
	// �ж�dwFoaλ���ĸ��ڱ�
	//PIMAGE_SECTION_HEADER pTempSectionHeader = pSectionHeader;
	for(int i = 0; i < pPEHeader->NumberOfSections; i++,pSectionHeader++)
	{
		if((dwFoa >= (pSectionHeader->PointerToRawData)) && (dwFoa <= (pSectionHeader->SizeOfRawData + pSectionHeader->PointerToRawData)))
		{
		    DWORD offset = dwFoa - (pSectionHeader->PointerToRawData);
			return pSectionHeader->VirtualAddress + offset;
		}
	}
	printf("�Ҳ���Foa %x ��Ӧ��Rva��ת��ʧ��\n",dwFoa);
	return 0;
}



//**************************************************************************								
//Align:��������Ĵ�С							
//����˵����								
//x: û�ж���ǰ�Ĵ�С��y:���ն��ٸ��ֽ�������															
//����ֵ˵����								
//DWORD ����x�����Ĵ�С								
//**************************************************************************
DWORD Align(int x, int y)
{
	// y����Ϊ��
	if(y == 0)
	{
		printf("�ļ������С����Ϊ��!\n");
		return -1;
	}
	// ����x / y���̺�����
	int quotient = x/y;
	int remainder = x%y;
	if(remainder == 0)
		return y * quotient;
	else
		return y * (quotient + 1);
}


//**************************************************************************								
//SetPEHeaderInfo:��ӡ��������Ϣ						
//����˵����								
//lpszFile��PE�ļ�����												
//����ֵ˵�������óɹ�����TRUE,ʧ�ܷ���FALSE								
//�޷���ֵ							
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
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return FALSE; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return FALSE;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	// ���ڴ洢PEͷ����Ϣ
	TCHAR szBuffer[128] = {0};
	// ������ڵ��ַ
	sprintf(szBuffer,"%x",pOptionalHeader->AddressOfEntryPoint);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_EntryPoint,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���þ����ַ
	sprintf(szBuffer,"%x",pOptionalHeader->ImageBase);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImageBase,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���þ����С
	sprintf(szBuffer,"%x",pOptionalHeader->SizeOfImage);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImageSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ô����ַ
	sprintf(szBuffer,"%x",pOptionalHeader->BaseOfCode);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BaseOfCode,WM_SETTEXT,0,(DWORD)szBuffer);
	// �������ݻ�ַ
	sprintf(szBuffer,"%x",pOptionalHeader->BaseOfData);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BaseOfData,WM_SETTEXT,0,(DWORD)szBuffer);
	// �����ڴ����
	sprintf(szBuffer,"%x",pOptionalHeader->SectionAlignment);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SectionAligent,WM_SETTEXT,0,(DWORD)szBuffer);
	// �����ļ�����
	sprintf(szBuffer,"%x",pOptionalHeader->FileAlignment);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_FileAligent,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ñ�־��
	sprintf(szBuffer,"%x",pOptionalHeader->LoaderFlags);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_MarkWord,WM_SETTEXT,0,(DWORD)szBuffer);
	// ������ϵͳ
	sprintf(szBuffer,"%x",pOptionalHeader->Subsystem);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SubSystem,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����������Ŀ
	sprintf(szBuffer,"%x",pPEHeader->NumberOfSections);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_NumberOfSections,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����ʱ���
	sprintf(szBuffer,"%x",pPEHeader->TimeDateStamp);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TimeDateStamp,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����PEͷ��С
	sprintf(szBuffer,"%x",pOptionalHeader->SizeOfHeaders);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SizeOfHeader,WM_SETTEXT,0,(DWORD)szBuffer);
	// ��������ֵ
	sprintf(szBuffer,"%x",pOptionalHeader->DllCharacteristics);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_Characteristics,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����У���
	sprintf(szBuffer,"%x",pOptionalHeader->CheckSum);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_CheckSum,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ÿ�ѡPEͷ
	sprintf(szBuffer,"%x",pPEHeader->SizeOfOptionalHeader);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_OptionalHeader,WM_SETTEXT,0,(DWORD)szBuffer);
	// Ŀ¼����Ŀ
	sprintf(szBuffer,"%x",pOptionalHeader->NumberOfRvaAndSizes);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_NumberOfDirectory,WM_SETTEXT,0,(DWORD)szBuffer);
	return TRUE;
}




//**************************************************************************								
//PrintDirectory:��ӡ��������Ϣ							
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
VOID PrintDataDirectory(IN LPSTR lpszFile, HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL; 								
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	DWORD count = 0; // ���ڸ�sprintf��������
	TCHAR PrintBuffer[0xFFFF] = {0}; // ����������е���Ϣ
	LPVOID pFileBuffer = NULL;
	
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return ;
	}
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	if(pOptionalHeader->DataDirectory[0].VirtualAddress != 0)
	{
		count = sprintf(PrintBuffer,"FileOffset = %x\r\n",RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[0].VirtualAddress));
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[0].VirtualAddress) + (DWORD)pFileBuffer);
		count += sprintf(PrintBuffer + count, "***********��������Ϣ*********************\r\n");
		count += sprintf(PrintBuffer + count, "ʱ���************************************\r\n");
		count += sprintf(PrintBuffer + count, "TimeDateStamp = %d\r\n",pExportDirectory->TimeDateStamp);
		count += sprintf(PrintBuffer + count, "�������ļ���******************************\r\n");
		count += sprintf(PrintBuffer + count, "Name = %s\r\n",(char*)(RvaToFileOffset(pFileBuffer,pExportDirectory->Name) + (DWORD)pFileBuffer));
		count += sprintf(PrintBuffer + count, "����������ʼ���**************************\r\n");
		count += sprintf(PrintBuffer + count, "Base = %d\r\n",pExportDirectory->Base);
		count += sprintf(PrintBuffer + count, "���е��������ĸ���************************\r\n");
		count += sprintf(PrintBuffer + count, "NumberOfFunctions = %d\r\n",pExportDirectory->NumberOfFunctions);
		count += sprintf(PrintBuffer + count, "�Ժ������ֵ����ĺ����ĸ���****************\r\n");
		count += sprintf(PrintBuffer + count, "NumberOfNames = %d\r\n",pExportDirectory->NumberOfNames);
		count += sprintf(PrintBuffer + count, "����������ַ��****************************\r\n");
		PDWORD AddrOfFuncsInFile = (PDWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfFunctions) + (DWORD)pFileBuffer);
		for(DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++,AddrOfFuncsInFile++)
		{
			count += sprintf(PrintBuffer + count,"����%d:0x%x\r\n",i,*AddrOfFuncsInFile);
		}
		PDWORD AddrOfNamesInFile = (PDWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNames) + (DWORD)pFileBuffer);
		for( i = 0; i < pExportDirectory->NumberOfNames; i++, AddrOfNamesInFile++)
		{
			count += sprintf(PrintBuffer + count, "����%d:%s\r\n",i,(char*)(RvaToFileOffset(pFileBuffer,*AddrOfNamesInFile) + (DWORD)pFileBuffer));
		}
		PWORD AddrOfNameOrdinalsInFile = (PWORD)(RvaToFileOffset(pFileBuffer,pExportDirectory->AddressOfNameOrdinals) + (DWORD)pFileBuffer);
		for( i = 0; i < pExportDirectory->NumberOfNames; i++, AddrOfNameOrdinalsInFile++)
		{
			count += sprintf(PrintBuffer + count, "����%d:%d\r\n",i,*AddrOfNameOrdinalsInFile);
		}
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("�����ı��༭����ִ��\n");
	}
	else 
	{
		
		sprintf(PrintBuffer,"���PE�ļ�û�е�����\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("�����ı��༭����ִ��\n");
	}
}

//**************************************************************************								
//PrintRelocation:��ӡ�ض�λ����Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
VOID PrintRelocation(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;								
    PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	DWORD count = 0; // ���ڸ�sprintf��������
	TCHAR PrintBuffer[0xFFFF] = {0}; // ����������е���Ϣ
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return ;
	}
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
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
			// ����ָ��ҳƫ�Ƶ�ָ��
			PWORD pBlockRva = (PWORD)((DWORD)pBaseRelocation + 8);
			for(DWORD i = 0; i < ((pBaseRelocation->SizeOfBlock - 8) / 2); i++,pBlockRva++)
			{
				count += sprintf(PrintBuffer + count,"��%x��:��ַ:%x  ����:%x\r\n",i,pBaseRelocation->VirtualAddress+((*pBlockRva)&0x0fff),(*pBlockRva)>>12);
			}
			pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);

		}
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("�����ı��༭����ִ��\n");
	}
	else
	{
		sprintf(PrintBuffer,"���PE�ļ�û���ض�λ��\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		DbgPrintf("�����ı��༭����ִ��\n");
	}
}



//**************************************************************************								
//PrintImportDescriptor:��ӡ�������Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
BOOL PrintImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	// ��FileBuffer�е�λ��
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	DWORD count = 0; // ���ڸ�sprintf��������
	TCHAR PrintBuffer[0x1FFFF] = {0}; // ����������е���Ϣ
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);


	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return 0;
	}
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[1].VirtualAddress) + (DWORD)pFileBuffer);
	// ���û������������־��ѭ����ӡ�������Ϣ 
	while(pImportDescriptor->OriginalFirstThunk  != 0)
	{
		// һ��DLL��һ��DLL�Ĵ�ӡ
		// ���ȴ�ӡDLL������
		count = sprintf(PrintBuffer,"*************************************\r\n");
		count += sprintf(PrintBuffer + count,"DLL Name: %s\r\n",(char*)(RvaToFileOffset(pFileBuffer,pImportDescriptor->Name) + (DWORD)pFileBuffer));
		// ���Ŵ�ӡDLL��INT��
		// ����ָ��FileBuffer��INT���ָ��
		PIMAGE_THUNK_DATA32 pINT = (PIMAGE_THUNK_DATA32)(RvaToFileOffset(pFileBuffer,pImportDescriptor->OriginalFirstThunk) + (DWORD)pFileBuffer);
		// ѭ����ӡINT��������־���ֽ�0
		while(pINT->u1.AddressOfData)
		{
			// �����ж�pINT�д����RVA���Ǻ���������ţ����λ�Ƿ�Ϊ1
			if((DWORD)pINT->u1.AddressOfData & 0x800000000)
			{
				// �����1��ֱ�Ӵ�ӡ�������������
				count += sprintf(PrintBuffer +count, "Ordinal Of Function: %x\r\n",pINT->u1.AddressOfData);
				pINT++;
			}
			else
			{
				// �ڸ���pINT�е�RVA�ҵ��������ƣ�ָ����һ���ṹ���ȶ���һ��ָ��
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer,(DWORD)pINT->u1.AddressOfData) + (DWORD)pFileBuffer);
				// ��ӡ��������
				count += sprintf(PrintBuffer + count, " Export Function Name: %s\r\n",(char*)(pImportByName->Name));
				pINT++;
			}
		}
		// �����ϵͳ����PE����ǰIAT��INT���ܲ�ͬ������Ĭ������ͬ�ģ�Ĭ�ϲ�֪���󶨵����
		// ����ָ��FileBuffer��IAT���ָ��
		PIMAGE_THUNK_DATA32 pIAT = (PIMAGE_THUNK_DATA32)(RvaToFileOffset(pFileBuffer,pImportDescriptor->FirstThunk) + (DWORD)pFileBuffer);
		// ѭ����ӡIAT��������־���ֽ�0
		while(pIAT->u1.AddressOfData)
		{
			// �����ж�pIAT�д����RVA���Ǻ���������ţ����λ�Ƿ�Ϊ1
			if((DWORD)pIAT->u1.AddressOfData & 0x800000000)
			{
				// �����1��ֱ�Ӵ�ӡ�������������
				count += sprintf(PrintBuffer + count,"Ordinal Of Function: %x\r\n",pIAT->u1.AddressOfData);
				pIAT++;
			}
			else
			{
				// �ڸ���pINT�е�RVA�ҵ��������ƣ�ָ����һ���ṹ���ȶ���һ��ָ��
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(RvaToFileOffset(pFileBuffer,(DWORD)pIAT->u1.AddressOfData) + (DWORD)pFileBuffer);
				// ��ӡ��������
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
//PrintBoundImportDescriptor:��ӡ�󶨵������Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//��ӡ�ɹ�����1��ʧ�ܷ���0							
//**************************************************************************
BOOL PrintBoundImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;								
	PIMAGE_NT_HEADERS pNTHeader = NULL;								
	PIMAGE_FILE_HEADER pPEHeader = NULL;								
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = NULL;
	// ��FileBuffer�е�λ��,�󶨵����ָ��
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = NULL;
	// ��ImageBuffer�е�λ�ã����ڼ��㺯������RVA
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptorInImageBuffer = NULL;
	DWORD count = 0; // ���ڸ�sprintf��������
	TCHAR PrintBuffer[0xFFFF] = {0}; // ����������е���Ϣ
	LPVOID pFileBuffer = NULL;
	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);

	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense");
		return 0;
	}
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return 0; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return 0;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	// ����Ŀ¼���еĵ�12��
	pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[11].VirtualAddress) + (DWORD)pFileBuffer);
	pBoundImportDescriptorInImageBuffer = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(pOptionalHeader->DataDirectory[11].VirtualAddress);
	// ���û�а󶨵����
	if (pBoundImportDescriptor == NULL)
	{
		sprintf(PrintBuffer,"���PE�ļ�û�а󶨵����\r\n");
		SendDlgItemMessage(hwndDlg,IDC_EDIT_TableInfo,WM_SETTEXT,0,(DWORD)PrintBuffer);
		return 0;
	}
	// ���û������������־��ѭ����ӡ�󶨵������Ϣ
	count = sprintf(PrintBuffer,"**********************************\r\n");
	while(pBoundImportDescriptor->TimeDateStamp + pBoundImportDescriptor->OffsetModuleName + pBoundImportDescriptor->NumberOfModuleForwarderRefs)
	{
		count += sprintf(PrintBuffer + count,"**********************************\r\n");
		// ���ȴ�ӡ����DLL������
		count += sprintf(PrintBuffer + count,"dll���ƣ�%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
		DbgPrintf("dll���ƣ�%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
		if(pBoundImportDescriptor->NumberOfModuleForwarderRefs)
		{
			// �ٴ�ӡIMAGE_BOUND_FORWARDER_REF�е�OffsetModulezָ��ĺ�����
			for(DWORD i = 0; i < pBoundImportDescriptor->NumberOfModuleForwarderRefs; i++,pBoundImportDescriptor++)
			{
				count += sprintf(PrintBuffer + count,"���뺯������%s\r\n",(char*)(RvaToFileOffset(pFileBuffer,(DWORD)pBoundImportDescriptorInImageBuffer + pBoundImportDescriptor->OffsetModuleName) + (DWORD)pFileBuffer));
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
//PrintResourceTable:��ӡ��Դ����Ϣ						
//����˵����								
//FileBuffer��pResDir ��Դ����ڣ� RootAddress ��Ŀ¼��ʼλ��											
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
BOOL PrintResourceTable(LPVOID pFileBuffer,PIMAGE_RESOURCE_DIRECTORY  pResDir,DWORD RootAddress,HWND hwndDlg)
{	
	if (pFileBuffer == NULL)
	{
		DbgPrintf("�ļ������쳣\n");
		return 0;
	}
	if (pResDir == NULL)
	{
		DbgPrintf("��Դ��ָ���쳣\n");
		return FALSE;
	}
	DWORD SumOfItems = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);
	DWORD count = 1;
	DWORD index = 0; // �����޸�PrintBufferָ��
	char PrintBuffer[0xffff] = {0}; // ���ڴ�Ŵ�ӡ��Ϣ
	while (count <= SumOfItems)
	{
		if(pResDirEntry->NameIsString)
		{
			PIMAGE_RESOURCE_DIR_STRING_U pResDirStr_U = (PIMAGE_RESOURCE_DIR_STRING_U)(pResDirEntry->NameOffset + RootAddress);
			index += sprintf(PrintBuffer + index,"��Դ��ţ�%s\r\n",pResDirStr_U->NameString);
		}
		else
		{
			index += sprintf(PrintBuffer + index,"��Դ��ţ�%x\r\n",pResDirEntry->Id);
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
//EnumSections: �����ڱ�����Ϣ�����ListView						
//����˵����								
//hwndDlg:���ھ����filename��PE�ļ�����															
//����ֵ˵����								
//�޷���ֵ			
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
	TCHAR buffer[0x20]; // ���ڴ洢�ڱ��еĸ�����Ϣת�����ַ���
	//��ʼ��
	memset(&lv,0,sizeof(LV_ITEM));
	lv.mask = LVIF_TEXT;

	//File-->FileBuffer
	ReadPEFile(lpszFile, &pFileBuffer);
	if(!pFileBuffer)
	{
		DbgPrintf("file-->buffer:failure");
		return FALSE ;
	}								
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return FALSE; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return FALSE;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pPEHeader->SizeOfOptionalHeader);
	for (DWORD i = 0 ;  i < pPEHeader->NumberOfSections; i++)
	{
	
		// ���ý���
		DbgPrintf("Section Name: %s\n",TEXT(pSectionHeader->Name));
		lv.pszText =TEXT((char*)pSectionHeader->Name);
		lv.iItem = i;
		lv.iSubItem = 0;
		ListView_InsertItem(hListModule,&lv);
		// �����ļ�ƫ��
		sprintf(buffer,"%x",pSectionHeader->PointerToRawData);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 1;
		ListView_SetItem(hListModule,&lv);
		// ���ô˽����ļ��еĴ�С
		sprintf(buffer,"%x",pSectionHeader->SizeOfRawData);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 2;
		ListView_SetItem(hListModule,&lv);
		// �����ڴ�ƫ��
		sprintf(buffer,"%x",pSectionHeader->VirtualAddress);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 3;
		ListView_SetItem(hListModule,&lv);
		// �����ڴ��С
		sprintf(buffer,"%x",pSectionHeader->Misc.VirtualSize);
		lv.pszText =TEXT(buffer);
		lv.iItem = i;
		lv.iSubItem = 4;
		ListView_SetItem(hListModule,&lv);
		// ���ýڵ�����
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
//EnumDataDirectory: ��������Ŀ¼�����Ϣ�����ListView						
//����˵����								
//hwndDlg:���ھ����filename��PE�ļ�����															
//����ֵ˵����								
//�޷���ֵ			
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
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return ; 							
	}	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);

	// ���ڴ��ÿ���������Rva��Size���ַ���
	TCHAR szBuffer[0x20] = {0};

	// ���õ������Rva��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[0].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[0].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���õ�����RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[1].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[1].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ������Դ���RVA��Siz
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[2].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ResourceRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[2].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ResourceSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// �����쳣���RVa��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[3].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExceptionRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[3].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_ExceptionSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ð�ȫ���RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[4].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SafeRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[4].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_SafeSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// �����ض�λ���RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[5].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_RelocationRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[5].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_RelocationSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���õ��Ա��RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[6].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DebugRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[6].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DebugSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ð�Ȩ���RVA��Siz
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[7].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_AuthorityRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[7].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_AuthoritySize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����ȫ��ָ����RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[8].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_GlobalPointerRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[8].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_GlobalPointerSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����Tls��RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[9].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[9].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���õ������ñ��RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[10].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_LoadConfRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[10].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_LoadConfSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ð󶨵�����RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[11].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BoundImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[11].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_BoundImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����IAT���RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[12].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[12].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// �����ӳٵ�����RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[13].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DelayImportRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[13].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_DelayImportSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ����COM���RVA��Size
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[14].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMRva,WM_SETTEXT,0,(DWORD)szBuffer);
	sprintf(szBuffer,"%x",pOptionalHeader->DataDirectory[14].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMSize,WM_SETTEXT,0,(DWORD)szBuffer);
	// ���ñ����ֶε�RVA��Size
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
	// ��FileBuffer�е�λ��
    PIMAGE_RESOURCE_DIRECTORY  pResourceDir_first = NULL;
	
	if(pFileBuffer == NULL)
	{
		DbgPrintf("the pointer to buffer is nosense\n");
		return ;
	}
	//�ж��Ƿ�����Ч��MZ��־								
	if(*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)								
	{								
		DbgPrintf("������Ч��MZ��־\n");							
		return ; 							
	}	

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)								
	{								
		DbgPrintf("������Ч��PE��־\n");														
		return ;							
	}
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);	
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pResourceDir_first = (PIMAGE_RESOURCE_DIRECTORY)(RvaToFileOffset(pFileBuffer,pOptionalHeader->DataDirectory[2].VirtualAddress) + (DWORD)pFileBuffer);
	PrintResourceTable(pFileBuffer,pResourceDir_first,(DWORD)pResourceDir_first,hwndDlg);
}
