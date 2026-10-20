#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <ras.h>
#include <cstddef>
#include <cstdio>

int main() {
    std::printf("{\"dial_size\":%zu,\"callback\":%zu,\"interface\":%zu,\"enc_password\":%zu,\"status_size\":%zu,\"local_endpoint\":%zu}\n",
        sizeof(RASDIALPARAMSW), offsetof(RASDIALPARAMSW,dwCallbackId),
        offsetof(RASDIALPARAMSW,dwIfIndex), offsetof(RASDIALPARAMSW,szEncPassword),
        sizeof(RASCONNSTATUSW), offsetof(RASCONNSTATUSW,localEndPoint));
}
