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

//��������								
//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile,OUT LPVOID* pFileBuffer);	

//**************************************************************************								


//**************************************************************************								
//SetPEHeaderInfo:��ӡ��������Ϣ						
//����˵����								
//lpszFile��PE�ļ�����												
//����ֵ˵�������óɹ�����TRUE,ʧ�ܷ���FALSE								
//�޷���ֵ							
//**************************************************************************
BOOL SetPEHeaderInfo(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintDirectory:��ӡ��������Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
VOID PrintDataDirectory(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintRelocation:��ӡ�ض�λ����Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
VOID PrintRelocation(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintImportDescriptor:��ӡ�������Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
BOOL PrintImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintBoundImportDescriptor:��ӡ�󶨵������Ϣ						
//����˵����								
//FileBuffer												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
BOOL PrintBoundImportDescriptor(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintSourceTable:��ӡ��Դ����Ϣ						
//����˵����								
//FileBuffer, ��Դ�����												
//����ֵ˵����								
//�޷���ֵ							
//**************************************************************************
BOOL PrintResourceTable(LPVOID pFileBuffer,PIMAGE_RESOURCE_DIRECTORY  pResDir,DWORD RootAddress,HWND hwndDlg);

//**************************************************************************								
//EnumSections: �����ڱ�����Ϣ�����ListView						
//����˵����								
//hwndDlg:���ھ����filename��PE�ļ�����															
//����ֵ˵����								
//�޷���ֵ			
//**************************************************************************
BOOL EnumSections(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//EnumDataDirectory: ��������Ŀ¼�����Ϣ�����ListView						
//����˵����								
//hwndDlg:���ھ����filename��PE�ļ�����															
//����ֵ˵����								
//�޷���ֵ			
//**************************************************************************
VOID EnumDataDirectory(IN LPSTR lpszFile,HWND hwndDlg);

//**************************************************************************								
//PrintResourceDir: ��ӡ��Դ��						
//����˵����								
//hwndDlg:���ھ����filename��PE�ļ�����															
//����ֵ˵����								
//�޷���ֵ			
//**************************************************************************
VOID TestPrintResourceDir(IN LPSTR lpszFile,HWND hwndDlg);

#endif
