#include "import_analyzer.h"
#include <cstring>

static const std::vector<std::string> SUSPICIOUS_APIS = {
   "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
   "NtUnmapViewOfSection","SetWindowsHookEx","GetAsyncKeyState",
   "InternetOpenUrl","HttpSendRequest","WinExec","ShellExecuteA",
   "RegSetValueEx","CryptEncrypt","IsDebuggerPresent","CreateToolhelp32Snapshot"

};


ImportReport analyzeImports(const PEInfo& pe) {
    ImportReport report;
    auto& opt=pe.nt->OptionalHeader;
    auto& importDir=opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!importDir.VirtualAddress) return report;

    
}