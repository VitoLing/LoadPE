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
	// ��ʼ��ͨ�ÿؼ�
	INITCOMMONCONTROLSEX  icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES; // ָ����һ��ͨ�ÿؼ���ICC_WIN95_CLASSES���������ؼ�
	InitCommonControlsEx(&icex);
	DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,DialogProc);
	return 0;
	
}