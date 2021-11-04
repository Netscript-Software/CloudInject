#include <iostream>
using namespace std;
#include "inject.h"

int main()
{
	printf("[+] Starting..\n");
	startbypass();
	try {
		if (initialize(FindProcessId("csgo.exe")) == 1) {
			printf("\n[+] Successfly injected.. You can use our cheat now!");
		}
		else {
			printf("\n[-] Something happened to when trying to inject..");
		}
	}
	catch (exception ex)
	{
		printf(ex.what());
	}
	printf("\n[?] Press enter to exit.");
	std::cin.get();
}