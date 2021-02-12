// LoadPE.cpp : Defines the entry point for the application.
//
#include "StdAfx.h"
#include "LoadPE.h"

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	hAppInstance = hInstance;
	// 初始化通用控件
	INITCOMMONCONTROLSEX  icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES; // 指定哪一类通用控件，ICC_WIN95_CLASSES包含其他控件
	InitCommonControlsEx(&icex);
	DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,DialogProc);
	return 0;
	
}