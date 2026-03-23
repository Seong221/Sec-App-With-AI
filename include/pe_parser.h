#pragma once
#include "pe_types.h"
#include <string>
#include <vector>

struct SectionInfo {
    std::string name;
    uint32_t virtualAddress;
    uint32_t rawSize;
    uint32_t rawOffset;
    uint32_t characteristics;
    double entropy;
};


struct PEInfo {
    uint8_t* base=nullptr;
    size_t fileSize=0;
    IMAGE_DOS_HEADER* dos=nullptr;
    IMAGE_NT_HEADERS* nt=nullptr;
    std::vector<SectionInfo> sections;
    bool is64bit=false;
    int fd=-1;
};

PEInfo loadPE(const std::string& path);
void unloadPE(PEInfo& pe);
uint8_t* rvaToPtr(const PEInfo& pe, uint32_t rva);

