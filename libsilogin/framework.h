#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Link required Windows crypto and shell libraries used by the implementation
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
// Smart card API
#pragma comment(lib, "winscard.lib")
