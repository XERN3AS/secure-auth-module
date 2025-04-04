#include <windows.h>
#include <stdio.h>

int authenticate(const char *username, const char *password) {
    HANDLE hToken;
    BOOL success;
    success = LogonUserA(username, NULL, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
    if (success) {
        CloseHandle(hToken);
        return 1;
    } else {
        printf("Error %lu\n", GetLastError());
        return 0;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <username> <password>\n", argv[0]);
        return 1;
    }
    if (authenticate(argv[1], argv[2])) {
        printf("Login OK\n");
        return 0;
    } else {
        printf("Login Failed\n");
        return 1;
    }
}