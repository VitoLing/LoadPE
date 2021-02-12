#ifndef PETOOLS_H
#define PETOOLS_H

#include "stdafx.h"
#include <windows.h>
#include <malloc.h>
#include <windef.h>
#include <stdlib.h>
#include <string.h>	
#include "resource.h"
#include <commctrl.h>
#include <commdlg.h>
#include "Tools.h"
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"comdlg32.lib")

//函数声明								
//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);	

//**************************************************************************								


//**************************************************************************								
//SetPEHeaderInfo:打印导出表信息						
//参数说明：								
//lpszFile：PE文件名称												
//返回值说明：设置成功返回TRUE,失败返回FALSE								
//无返回值							
//**************************************************************************
BOOL SetPEHeaderInfo(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintDirectory:打印导出表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
VOID PrintDataDirectory(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintRelocation:打印重定位表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
VOID PrintRelocation(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintImportDescriptor:打印导入表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
BOOL PrintImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintBoundImportDescriptor:打印绑定导入表信息						
//参数说明：								
//FileBuffer												
//返回值说明：								
//无返回值							
//**************************************************************************
BOOL PrintBoundImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintSourceTable:打印资源表信息						
//参数说明：								
//FileBuffer, 资源表入口												
//返回值说明：								
//无返回值							
//**************************************************************************
BOOL PrintResourceTable(LPVOID pFileBuffer,PIMAGE_RESOURCE_DIRECTORY  pResDir,DWORD RootAddress,HWND hwndDlg);

//**************************************************************************								
//EnumSections: 遍历节表，将信息输出到ListView						
//参数说明：								
//hwndDlg:窗口句柄，filename：PE文件名称															
//返回值说明：								
//无返回值			
//**************************************************************************
BOOL EnumSections(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//EnumDataDirectory: 遍历数据目录项，将信息输出到ListView						
//参数说明：								
//hwndDlg:窗口句柄，filename：PE文件名称															
//返回值说明：								
//无返回值			
//**************************************************************************
VOID EnumDataDirectory(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintResourceDir: 打印资源表						
//参数说明：								
//hwndDlg:窗口句柄，filename：PE文件名称															
//返回值说明：								
//无返回值			
//**************************************************************************
VOID TestPrintResourceDir(IN LPSTR lpszFile,HWND hwndDlg);

#endif
