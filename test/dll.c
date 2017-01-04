#include <windows.h>

#pragma comment(lib, "user32.lib")

__declspec(dllexport)
int
Add(short arg1, short arg2)
{
	return arg1 + arg2;
}

__declspec(dllexport)
void
Alert(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	MessageBox(0, lpszCmdLine, "Alert", MB_OK);
}
