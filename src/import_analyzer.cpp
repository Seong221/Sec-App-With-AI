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

    auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)rvaToPtr(pe, importDir.VirtualAddress);
    if(!desc)return report;

    while(desc->Name) {
        ImportEntry entry;
        char* dllName=(char*)rvaToPtr(pe,desc->Name);
        if(!dllName){desc++;continue;}
        entry.dll=dllName;

        uint32_t* thunk=(uint32_t*)rvaToPtr(pe, desc->OriginalFirstThunk?desc->OriginalFirstThunk:desc->FirstThunk);
        
        while(thunk&&*thunk) {
            if(!(*thunk&0x80000000)) {
                auto* ibn=(IMAGE_IMPORT_BY_NAME*)rvaToPtr(pe,*thunk);
                if(ibn) {
                    std::string fname=ibn->Name;
                    entry.functions.push_back(fname);
                    for(auto& s: SUSPICIOUS_APIS) {
                        if(fname==s){
                            report.suspiciousApis.push_back(fname);
                            report.score += 10;
                        }
                    }
                }
            }
            thunk++;
        }
        report.imports.push_back(entry);
        desc++;
    }
    return report;

    
}