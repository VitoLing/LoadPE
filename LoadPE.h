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

// 遍历进程函数
VOID EnumProcess(HWND hListProcess)
{
	// 向列表控件中插入一行
	LV_ITEM vitem;
	//初始化
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask = LVIF_TEXT;

	PROCESSENTRY32 pe32; // 进程结构
	pe32.dwSize = sizeof(pe32);  // 在使用这个结构前，先设置它的大小
	// 给系统内所有的进程拍个快照
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	// 某个进程所有的DLL快照句柄
	HANDLE hModuleSnap = NULL;
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		// 输出错误信息
		return;
	}
	BOOL bMore = Process32First(hProcessSnap,&pe32);
	// HANDLE hProcess = 0;
	// WCHAR procPath[_MAX_PATH] = {0};
	MODULEENTRY32 lpme; // DLL结构
	lpme.dwSize = sizeof(MODULEENTRY32); // 在使用这个结构前，先设置它的大小
	DWORD row = 0; // 初始化行号，要在循环中递增
	BOOL bRet = FALSE;
	char bufferPID[20] = {0}; // 用于将PID，镜像基址，镜像大小unsigned long类型的值转化为char*类型
	char bufferModBaseAddr[20] = {0};
	char bufferImageSize[20] = {0};
	while(bMore)
	{
		/*
		// 打开一个已存在的进程对象，并返回进程的句柄
		hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pe32.th32ProcessID);
		// 得到该进程的全路径
		GetModuleFileNameEx(hProcess,NULL,procPath,_MAX_PATH);
		*/
		// 设置第row行第0列，进程名称
		vitem.pszText = TEXT(pe32.szExeFile); // 在第零行第零列要插入的文本
		vitem.iItem = row; // 递增的行
		vitem.iSubItem = 0; // 列号
		ListView_InsertItem(hListProcess,&vitem); // 本质上还是SendMessage函数实现，一切皆窗口，一切皆消息
	    // 设置第row行第1列，进程PID
		_ultoa(pe32.th32ProcessID,bufferPID,10);
		vitem.pszText = TEXT(bufferPID);
		vitem.iItem = row;
		vitem.iSubItem = 1;
		ListView_SetItem(hListProcess,&vitem);
		// 给一个已存在的进程内所有的DLL拍个快照
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe32.th32ProcessID);
		bRet = Module32First(hModuleSnap,&lpme);
		if (bRet)
		{
			// 获取镜像基址
			// 设置第row行第2列，镜像基址
			_ultoa((unsigned long)(lpme.modBaseAddr),bufferModBaseAddr,16);
			
			DbgPrintf("modBaseAddr: %2x\n",lpme.modBaseAddr);
			vitem.pszText = TEXT(bufferModBaseAddr);
			vitem.iItem = row;
			vitem.iSubItem = 2;
			ListView_SetItem(hListProcess,&vitem);

		}
		// 遍历DLL快照，找到进程的最后一个模块从而计算出镜像大小
		do 
		{
			bRet = Module32Next(hModuleSnap,&lpme);
		} while (bRet);
		// 设置第row行第3列,镜像大小
		_ultoa((unsigned long)(lpme.modBaseAddr) + (unsigned long)lpme.modBaseSize,bufferImageSize,16);
		vitem.pszText = TEXT(bufferImageSize);
		vitem.iItem = row;
		vitem.iSubItem = 3;
	    ListView_SetItem(hListProcess,&vitem);
		bMore = Process32Next(hProcessSnap,&pe32);
		row++;
	}
	
}

// 遍历指定进程的模块
VOID EnumModules(HWND hwndDlg,WPARAM wParam, LPARAM lParam)
{
	DWORD dwRowId;
	TCHAR szPid[0x20];
	TCHAR buffer[0x20]; // 用于存放模块的ImageBase和SizeOfImage
	HANDLE	hModuleSnap = NULL;
	HWND hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	HWND hListModule = GetDlgItem(hwndDlg,IDC_LIST_MODULE);
	MODULEENTRY32 lpme; // DLL结构
	lpme.dwSize = sizeof(MODULEENTRY32);
	BOOL bRet = FALSE;
	LV_ITEM lv;

	//初始化
	memset(&lv,0,sizeof(LV_ITEM));
	memset(szPid,0,0x20);
	//获取选择行
	dwRowId = SendMessage(hListProcess,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if (dwRowId == -1)
	{
		MessageBox(NULL,TEXT("请选择进程"),TEXT("出错啦"),MB_OK);
		return;
	}
	//获取PID
	lv.iSubItem = 1;				//要获取的列
    lv.pszText = szPid;             //指定存储查询结果的缓冲区
	lv.cchTextMax = 0x20;			//指定缓冲区大小
	SendMessage(hListProcess, LVM_GETITEMTEXT, dwRowId, (DWORD)&lv);
	// 给一个已存在的进程内所有的DLL拍个快照
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, strtoul(szPid,(char**)NULL,10));
	bRet = Module32First(hModuleSnap,&lpme);
	DWORD row = 0; // 初始化行号，要在循环中
	// 循环前应先清空列表
    SendMessage(hListModule,LVM_DELETEALLITEMS,0,0);
	while(bRet)
	{
		// 设置模块名称
		lv.pszText = lpme.szModule;
		lv.iItem = row;
		lv.iSubItem = 0;
		ListView_InsertItem(hListModule,&lv);
		// 设置模块基址
		_ultoa((unsigned long)(lpme.modBaseAddr),buffer,16);
		lv.pszText = TEXT(buffer);
		lv.iItem = row;
		lv.iSubItem = 1;
		ListView_SetItem(hListModule,&lv);
		// 设置模块大小
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

// 初始化进程列表控件
VOID InitProcessListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;

	// 初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	// 获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);

	// 设置整行选中
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);

	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("进程"); // 列标题
	lv.cx = 150;   // 列宽
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// 第二列
	lv.pszText = TEXT("PID");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);
	// 第三列
	lv.pszText = TEXT("镜像基址");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,2,(DWORD)&lv);
	// 第四列
	lv.pszText = TEXT("镜像大小");
	lv.cx = 150;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess,3,&lv);
	EnumProcess(hListProcess);
}

//初始化模块列表控件
VOID InitModuleListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListModule;
	
	// 初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	// 获取IDC_LIST_PROCESS句柄
	hListModule = GetDlgItem(hwndDlg,IDC_LIST_MODULE);
	
	// 设置整行选中
	SendMessage(hListModule,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("模块名称"); // 列标题
	lv.cx = 150;   // 列宽
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModule,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// 第二列
	lv.pszText = TEXT("模块基址");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModule,1,&lv);
	// 第三列
	lv.pszText = TEXT("模块大小");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListModule,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,1,(DWORD)&lv);

}

// 初始化节表列表控件
VOID InitSectionListView(HWND hwndDlg)
{
	LV_COLUMN lv;
	HWND hListModule;

	// 初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	// 获取IDC_LIST_PROCESS句柄
	hListModule = GetDlgItem(hwndDlg,IDC_LIST_SECTIONS);

	// 设置整行选中
	SendMessage(hListModule,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	
	// 第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("节名name"); // 列标题
	lv.cx = 150;   // 列宽
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModule,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	// 第二列
	lv.pszText = TEXT("文件偏移");
	lv.cx = 150;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModule,1,&lv);
	// 第三列
	lv.pszText = TEXT("文件大小");
	lv.cx = 150;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListModule,2,&lv);
	// 第四列
	lv.pszText = TEXT("内存偏移");
	lv.cx = 150;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListModule,3,&lv); 
	// 第五列
	lv.pszText = TEXT("内存大小");
	lv.cx = 150;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListModule,4,&lv);
	// 第六列
	lv.pszText = TEXT("节区属性");
	lv.cx = 150;
	lv.iSubItem = 5;
	ListView_InsertColumn(hListModule,5,&lv);

	EnumSections(szFileName,hListModule);

}
// 节表窗口回调函数
BOOL CALLBACK ProcDlgSections(HWND hwndDlg,UINT uMsg,WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// 初始化节表
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

// 目录具体信息打印窗口回调函数(打印导出表信息，如果有的话）
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

// 目录具体信息打印窗口回调函数(打印重定位表信息，如果有的话）
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

// 目录具体信息打印窗口回调函数(打印导入表信息）
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

// 目录具体信息打印窗口回调函数(打印绑定导入表信息）
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

// 目录具体信息打印窗口回调函数(打印资源表信息）
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


// 数据目录项窗口回调函数
BOOL CALLBACK ProcDlgDirectory(HWND hwndDlg, UINT uMsg, WPARAM wParam,LPARAM lParam)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			// 初始化10个数据目录项
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
					// 打开一个新的窗口，输出导入表信息
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgImportButton);
					break;
				}
			case IDC_BUTTON_ExportTable:
				{
					// 打开一个窗口，输出导出表信息
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgExportButton);
					break;
				}
			case IDC_BUTTON_ResourceTable:
				{
					// 打开一个窗口，打印资源表信息
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgResourceButton);
					break;
				}
			case  IDC_BUTTON_RelocationTable:
				{
					// 打开一个窗口，打印重定位表信息
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgRelocationButton);
					break;
				}
			case IDC_BUTTON_BoundImportTable:
				{
					// 打开一个窗口，打印绑定导入表
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_TableInfo),hwndDlg,ProcDlgBoundImportButton);
					break;
				}
			case IDC_BUTTON_IAT:
				{
					// 打开一个窗口，打印IAT表
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
// PE窗口回调函数
BOOL CALLBACK ProcDlgPE(HWND hwndDlg,UINT uMsg,WPARAM wParam, LPARAM lParam)
{
	BOOL bRet = FALSE;
	switch(uMsg)
	{

	case WM_INITDIALOG:
		{
			// 打开PE文件 获取相关信息,并设置PE头信息
			SetPEHeaderInfo(szFileName,hwndDlg);
			DbgPrintf("子窗口初始化调用\n");

			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			return TRUE;
		}
	// 接收按钮消息
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
				// 关闭按钮
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

// 关于按钮回调函数
BOOL CALLBACK ProcDlgAbout(HWND hwndDlg,UINT uMsg,WPARAM wParam, LPARAM lParam)
{
	char PrintBuffer[0xffff] = {0}; // 用于存储要打印的内容
	DWORD count = 0; // 用于计数

	switch(uMsg)
	{
		
	case WM_INITDIALOG:
		{
			count = sprintf(PrintBuffer,"本应用是在Windows xp系统上使用VC++6.0开发的\r\n");
			count += sprintf(PrintBuffer + count,"所以这个应用它就没什么用，在64位的Windows系统上并不是所有的功能都能实现\r\n");
			count += sprintf(PrintBuffer + count,"虽然没什么用，但我还是大概说一下它的功能：除了解析PE文件外\r\n");
			count += sprintf(PrintBuffer + count,"最大的作用就是气人，因为它还有很多BUG\r\n");
			count += sprintf(PrintBuffer + count,"所以还希望各位大神帮我解决这些问题，顺便给我点个星\r\n");
			count += sprintf(PrintBuffer + count,"我会不定期的维护这个应用，但主要的目的还是为了学习和记录\r\n");
			count += sprintf(PrintBuffer + count,"最后，管你看没看懂，用就完事了\r\n");
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
// 主窗口回调函数
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
	// 初始化主窗口时，需要完成的任务
	case WM_INITDIALOG:
		{
			InitProcessListView(hwndDlg);
			InitModuleListView(hwndDlg);
			break;
		}
	// 点击右上角的×关闭对话框
	case  WM_CLOSE:
		{
			EndDialog(hwndDlg,0);
			break;
		}
	// 接收通用控件消息
	case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*)lParam;
			if(wParam == IDC_LIST_PROCESS2 && pNMHDR->code == NM_CLICK)
			{
				EnumModules(hwndDlg,wParam,lParam);
			}
			break;
		}
	// 接收按钮消息						
	case  WM_COMMAND :	 							
		{
		switch (LOWORD (wParam))							
		{
			
		// “PE查看”按钮
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
				// 打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE),hwndDlg,ProcDlgPE);
				break;
			}

		// “关于”按钮
		case IDC_BUTTON_ABOUT:
			{
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_ABOUT),hwndDlg,ProcDlgAbout);
				return TRUE;
			}

		// “退出”按钮
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