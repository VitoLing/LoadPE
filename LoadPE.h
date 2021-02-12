#include "StdAfx.h"
#include "resource.h"
#include <commctrl.h>
#include <commdlg.h>
#include "Tools.h"
#include "PETools.h"
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"comdlg32.lib")

HINSTANCE hAppInstance = NULL;
TCHAR szPeFileExt[100] = "*.exe;*.dll;*,scr;*.drv;*.sys";
TCHAR szFileName[256];

// �������̺���
VOID EnumProcess(HWND hListProcess)
{
	// ���б�ؼ��в���һ��
	LV_ITEM vitem;
	//��ʼ��
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;

	PROCESSENTRY32 pe32; // ���̽ṹ
	pe32.dwSize = sizeof(pe32);  // ��ʹ������ṹǰ�����������Ĵ�С
	// ��ϵͳ�����еĽ����ĸ�����
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	// ĳ���������е�DLL���վ��
	HANDLE hModuleSnap = NULL;
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		// ���������Ϣ
		return;
	}
	BOOL bMore = Process32First(hProcessSnap,&pe32);
	// HANDLE hProcess = 0;
	// WCHAR procPath[_MAX_PATH] = {0};
	MODULEENTRY32 lpme; // DLL�ṹ
	lpme.dwSize = sizeof(MODULEENTRY32); // ��ʹ������ṹǰ�����������Ĵ�С
	DWORD row = 0; // ��ʼ���кţ�Ҫ��ѭ���е���
	BOOL bRet = FALSE;
	char bufferPID[20] = {0}; // ���ڽ�PID�������ַ�������Сunsigned long���͵�ֵת��Ϊchar*����
	char bufferModBaseAddr[20] = {0};
	char bufferImageSize[20] = {0};
	while(bMore)
	{
		/*
		// ��һ���Ѵ��ڵĽ��̶��󣬲����ؽ��̵ľ��
		hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pe32.th32ProcessID);
		// �õ��ý��̵�ȫ·��
		GetModuleFileNameEx(hProcess,NULL,procPath,_MAX_PATH);
		*/
		// ���õ�row�е�0�У���������
		vitem.pszText = TEXT(pe32.szExeFile); // �ڵ����е�����Ҫ������ı�
		vitem.iItem = row; // ��������
		vitem.iSubItem = 0; // �к�
		ListView_InsertItem(hListProcess,&vitem); // �����ϻ���SendMessage����ʵ�֣�һ�нԴ��ڣ�һ�н���Ϣ
	    // ���õ�row�е�1�У�����PID
		_ultoa(pe32.th32ProcessID,bufferPID,10);
		vitem.pszText = TEXT(bufferPID);
		vitem.iItem = row;
		vitem.iSubItem = 1;
		ListView_SetItem(hListProcess,&vitem);
		// ��һ���Ѵ��ڵĽ��������е�DLL�ĸ�����
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		bRet = Module32First(hModuleSnap,&lpme);
		if (bRet)
		{
			// ��ȡ�����ַ
			// ���õ�row�е�2�У������ַ
			_ultoa((unsigned long)(lpme.modBaseAddr),bufferModBaseAddr,16);
			
			DbgPrintf("modBaseAddr: %2x\n",lpme.modBaseAddr);
			vitem.pszText = TEXT(bufferModBaseAddr);
			vitem.iItem = row;
			vitem.iSubItem = 2;
			ListView_SetItem(hListProcess,&vitem);

		}
		// ����DLL���գ��ҵ����̵����һ��ģ��Ӷ�����������С
		do 
		{
			bRet = Module32Next(hModuleSnap,&lpme);
		} while (bRet);
		// ���õ�row�е�3��,�����С
		_ultoa((unsigned long)(lpme.modBaseAddr) + (unsigned long)lpme.modBaseSize,bufferImageSize,16);
		vitem.pszText = TEXT(bufferImageSize);
		vitem.iItem = row;
		vitem.iSubItem = 3;
	    ListView_SetItem(hListProcess,&vitem);
		bMore = Process32Next(hProcessSnap,&pe32);
		row++;
	}
	
}

// ����ָ�����̵�ģ��
VOID EnumModules(HWND hwndDlg,WPARAM wParam, LPARAM lParam)
{
	DWORD dwRowId;
	TCHAR szPid[0x20];
	TCHAR buffer[0x20]; // ���ڴ��ģ���ImageBase��SizeOfImage
	HANDLE	hModuleSnap = NULL;
	HWND hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	HWND hListModule = GetDlgItem(hwndDlg,IDC_LIST_MODULE);
	MODULEENTRY32 lpme; // DLL�ṹ
	lpme.dwSize = sizeof(MODULEENTRY32);
	BOOL bRet = FALSE;
	LV_ITEM lv;

	//��ʼ��
	memset(&lv,0,sizeof(LV_ITEM));
	memset(szPid,0,0x20);
	//��ȡѡ����
	dwRowId = SendMessage(hListProcess,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL,TEXT("��ѡ�����"),TEXT("������"),MB_OK);
		return;
	}
	//��ȡPID
	lv.iSubItem = 1;				//Ҫ��ȡ����
    lv.pszText = szPid;             //ָ���洢��ѯ����Ļ�����
	lv.cchTextMax = 0x20;			//ָ����������С
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);
	// ��һ���Ѵ��ڵĽ��������е�DLL�ĸ�����
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, strtoul(szPid,(char**)NULL,10));
	bRet = Module32First(hModuleSnap,&lpme);
	DWORD row = 0; // ��ʼ���кţ�Ҫ��ѭ����
	// ѭ��ǰӦ������б�
    SendMessage(hListModule,LVM_DELETEALLITEMS,0,0);
	while(bRet)
	{
		// ����ģ������
		lv.pszText = lpme.szModule;
		lv.iItem = row;
		lv.iSubItem = 0;
		ListView_InsertItem(hListModule,&lv);
		// ����ģ���ַ
		_ultoa((unsigned long)(lpme.modBaseAddr),buffer,16);
		lv.pszText = TEXT(buffer);
		lv.iItem = row;
		lv.iSubItem = 1;
		ListView_SetItem(hListModule,&lv);
		// ����ģ���С
		_itoa(lpme.modBaseSize,buffer,16);
		lv.pszText = TEXT(buffer);
		lv.iItem = row;
		lv.iSubItem = 2;
		ListView_SetItem(hListModule,&lv);
		bRet = Module32Next(hModuleSnap,&lpme);
		row++;
	}
    DbgPrintf("PID:%d\n",strtoul(szPid,(char**)NULL,10));
	// MessageBox(NULL,szPid,TEXT("PID"),MB_OK);
}

// ��ʼ�������б�ؼ�
VOID InitProcessListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;

	// ��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	// ��ȡIDC_LIST_PROCESS���
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);

	// ��������ѡ��
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	// ��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("����"); // �б���
	lv.cx = 150;   // �п�
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// �ڶ���
	lv.pszText = TEXT("PID");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);
	// ������
	lv.pszText = TEXT("�����ַ");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,2,(DWORD)&lv);
	// ������
	lv.pszText = TEXT("�����С");
	lv.cx = 150;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess,3,&lv);
	EnumProcess(hListProcess);
}

//��ʼ��ģ���б�ؼ�
VOID InitModuleListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListModule;
	
	// ��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	// ��ȡIDC_LIST_PROCESS���
	hListModule = GetDlgItem(hwndDlg,IDC_LIST_MODULE);
	
	// ��������ѡ��
	SendMessage(hListModule,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	
	// ��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("ģ������"); // �б���
	lv.cx = 150;   // �п�
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModule,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// �ڶ���
	lv.pszText = TEXT("ģ���ַ");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModule,1,&lv);
	// ������
	lv.pszText = TEXT("ģ���С");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListModule,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);

}

// ��ʼ���ڱ��б�ؼ�
VOID InitSectionListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListModule;

	// ��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	// ��ȡIDC_LIST_PROCESS���
	hListModule = GetDlgItem(hwndDlg,IDC_LIST_SECTIONS);

	// ��������ѡ��
	SendMessage(hListModule,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	
	// ��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("����name"); // �б���
	lv.cx = 150;   // �п�
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModule,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// �ڶ���
	lv.pszText = TEXT("�ļ�ƫ��");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModule,1,&lv);
	// ������
	lv.pszText = TEXT("�ļ���С");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListModule,2,&lv);
	// ������
	lv.pszText = TEXT("�ڴ�ƫ��");
	lv.cx = 150;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListModule,3,&lv); 
	// ������
	lv.pszText = TEXT("�ڴ��С");
	lv.cx = 150;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListModule,4,&lv);
	// ������
	lv.pszText = TEXT("��������");
	lv.cx = 150;
	lv.iSubItem = 5;
	ListView_InsertColumn(hListModule,5,&lv);

	EnumSections(szFileName,hListModule);

}
// �ڱ��ڻص�����
BOOL CALLBACK ProcDlgSections(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// ��ʼ���ڱ�
			InitSectionListView(hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// Ŀ¼������Ϣ��ӡ���ڻص�����(��ӡ��������Ϣ������еĻ���
BOOL CALLBACK ProcDlgExportButton(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{

			PrintDataDirectory(szFileName,hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// Ŀ¼������Ϣ��ӡ���ڻص�����(��ӡ�ض�λ����Ϣ������еĻ���
BOOL CALLBACK ProcDlgRelocationButton(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			
			PrintRelocation(szFileName,hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// Ŀ¼������Ϣ��ӡ���ڻص�����(��ӡ�������Ϣ��
BOOL CALLBACK ProcDlgImportButton(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			
			PrintImportDescriptor(szFileName,hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// Ŀ¼������Ϣ��ӡ���ڻص�����(��ӡ�󶨵������Ϣ��
BOOL CALLBACK ProcDlgBoundImportButton(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			
			PrintBoundImportDescriptor(szFileName,hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}

// Ŀ¼������Ϣ��ӡ���ڻص�����(��ӡ��Դ����Ϣ��
BOOL CALLBACK ProcDlgResourceButton(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{	
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			
			TestPrintResourceDir(szFileName,hwndDlg);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}


// ����Ŀ¼��ڻص�����
BOOL CALLBACK ProcDlgDirectory(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// ��ʼ��10������Ŀ¼��
			EnumDataDirectory(szFileName,hwndDlg);

			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDC_BUTTON_ImportTable:
				{
					// ��һ���µĴ��ڣ�����������Ϣ
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgImportButton);
					break;
				}
			case IDC_BUTTON_ExportTable:
				{
					// ��һ�����ڣ������������Ϣ
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgExportButton);
					break;
				}
			case IDC_BUTTON_ResourceTable:
				{
					// ��һ�����ڣ���ӡ��Դ����Ϣ
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgResourceButton);
					break;
				}
			case  IDC_BUTTON_RelocationTable:
				{
					// ��һ�����ڣ���ӡ�ض�λ����Ϣ
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgRelocationButton);
					break;
				}
			case IDC_BUTTON_BoundImportTable:
				{
					// ��һ�����ڣ���ӡ�󶨵����
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgBoundImportButton);
					break;
				}
			case IDC_BUTTON_IAT:
				{
					// ��һ�����ڣ���ӡIAT��
				//	DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgIATButton);
					break;
				}
			case IDC_BUTTON_TableClose:
				{
					EndDialog(hwndDlg,0);
					return TRUE;
				}
			}
			break;
		}
		break;
	}
	return FALSE;
}
// PE���ڻص�����
BOOL CALLBACK ProcDlgPE(HWND hwndDlg,UINT uMsg,WPARAM wParam, LPARAM lParam)
{
	BOOL bRet = FALSE;
	switch(uMsg)
	{

	case WM_INITDIALOG:
		{
			// ��PE�ļ� ��ȡ�����Ϣ,������PEͷ��Ϣ
			SetPEHeaderInfo(szFileName,hwndDlg);
			DbgPrintf("�Ӵ��ڳ�ʼ������\n");

			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
	// ���հ�ť��Ϣ
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
				// �رհ�ť
			case IDC_BUTTON_PE_CLOSE:
				{
					EndDialog(hwndDlg,0);
					return TRUE;
				}
			case IDC_BUTTON_SECTION:
				{
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_SECTIONS),hwndDlg,ProcDlgSections);
					break;
				}
			case IDC_BUTTON_DIRECTORY:
				{
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_DataDirectory),hwndDlg,ProcDlgDirectory);
					break;
				}
				break;
			}
			break;
		}
	}
	return FALSE;
}

// ���ڰ�ť�ص�����
BOOL CALLBACK ProcDlgAbout(HWND hwndDlg,UINT uMsg,WPARAM wParam, LPARAM lParam)
{
	char PrintBuffer[0xffff] = {0}; // ���ڴ洢Ҫ��ӡ������
	DWORD count = 0; // ���ڼ���

	switch(uMsg)
	{
		
	case WM_INITDIALOG:
		{
			count = sprintf(PrintBuffer,"��Ӧ������Windows xpϵͳ��ʹ��VC++6.0������\r\n");
			count += sprintf(PrintBuffer + count,"�������Ӧ������ûʲô�ã���64λ��Windowsϵͳ�ϲ��������еĹ��ܶ���ʵ��\r\n");
			count += sprintf(PrintBuffer + count,"��Ȼûʲô�ã����һ��Ǵ��˵һ�����Ĺ��ܣ����˽���PE�ļ���\r\n");
			count += sprintf(PrintBuffer + count,"�������þ������ˣ���Ϊ�����кܶ�BUG\r\n");
			count += sprintf(PrintBuffer + count,"���Ի�ϣ����λ������ҽ����Щ���⣬˳����ҵ����\r\n");
			count += sprintf(PrintBuffer + count,"�һ᲻���ڵ�ά�����Ӧ�ã�����Ҫ��Ŀ�Ļ���Ϊ��ѧϰ�ͼ�¼\r\n");
			count += sprintf(PrintBuffer + count,"��󣬹��㿴û�������þ�������\r\n");
			SendDlgItemMessage(hwndDlg,IDC_EDIT_ABOUT,WM_SETTEXT,0,(DWORD)PrintBuffer);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}
// �����ڻص�����
BOOL CALLBACK DialogProc(
						 HWND hwndDlg,  // handle to dialog box			
						 UINT uMsg,     // message			
						 WPARAM wParam, // first message parameter			
						 LPARAM lParam  // second message parameter			
						 )			
{									
	OPENFILENAME stOpenFile;
	switch(uMsg)								
	{
	// ��ʼ��������ʱ����Ҫ��ɵ�����
	case WM_INITDIALOG:
		{
			InitProcessListView(hwndDlg);
			InitModuleListView(hwndDlg);
			break;
		}
	// ������Ͻǵġ��رնԻ���
	case  WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			break;
		}
	// ����ͨ�ÿؼ���Ϣ
	case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*)lParam;
			if(wParam == IDC_LIST_PROCESS2 && pNMHDR->code == NM_CLICK)
			{
				EnumModules(hwndDlg,wParam,lParam);
			}
			break;
		}
	// ���հ�ť��Ϣ						
	case  WM_COMMAND :	 							
		{
		switch (LOWORD (wParam))							
		{
			
		// ��PE�鿴����ť
		case IDC_BUTTON_OPEN:
			{
				memset(&szFileName,0,256);
				memset(&stOpenFile,0,sizeof(OPENFILENAME));
				stOpenFile.lStructSize = sizeof(OPENFILENAME);
				stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
				stOpenFile.hwndOwner = hwndDlg;
				stOpenFile.lpstrFilter = szPeFileExt;
				stOpenFile.lpstrFile = szFileName;
				stOpenFile.nMaxFile = MAX_PATH;
				GetOpenFileName(&stOpenFile);
				// MessageBox(0,szFileName,0,0);
				// ���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE),hwndDlg,ProcDlgPE);
				break;
			}

		// �����ڡ���ť
		case IDC_BUTTON_ABOUT:
			{
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_ABOUT),hwndDlg,ProcDlgAbout);
				return TRUE;
			}

		// ���˳�����ť
		case IDC_BUTTON_LOGOUT:
			{
				EndDialog(hwndDlg,0);
				break;
			}
		}
		break;
		}
    }									
	
	return FALSE ;								
}