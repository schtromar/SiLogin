#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
// Link required Windows libraries used by the provider
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winscard.lib")
// Additional libs for credential provider and security APIs
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "credui.lib")
