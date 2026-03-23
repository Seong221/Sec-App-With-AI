#include "pe_parser.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdexcept>
#include <cstring>

PEInfo loadPE(const std::string& path) {
    PEInfo pe;
    pe.fd=open(path.c_str(), O_RDONLY);
    if(pe.fd<0) throw std::runtime_error("Cannot open file: "+path);

    struct stat st;
    fstat(pe.fd, &st);
    pe.fileSize=st.st_size;

    pe.base=(uint8_t*)mmap(nullptr, pe.fileSize, PROT_READ, MAP_PRIVATE, pe.fd, 0);
    if (pe.base==MAP_FAILED) throw std::runtime_error("mmap failed");

    pe.dos=(IMAGE_DOS_HEADER*)pe.base;
    if(pe.dos->e_magic!=MZ_MAGIC) throw std::runtime_error("Not a valid PE: bad MZ magic");

    pe.nt=(IMAGE_NT_HEADERS*)(pe.base+pe.dos->e_lfanew);
    if(pe.nt->Signature!=PE_MAGIC)throw std::runtime_error("Not a valid PE: bad PE signature");

    pe.is64bit = (pe.nt->OptionalHeader.Magic==PE32P_MAGIC);

    auto* secHeader = (IMAGE_SECTION_HEADER*)(
        (uint8_t*)&pe.nt->OptionalHeader+pe.nt->FileHeader.SizeOfOptionalHeader
    );

    for(int i=0; i<pe.nt->FileHeader.NumberOfSections; i++){
        SectionInfo sec;
        sec.name=std::string((char*)secHeader[i].Name,8);
        sec.name=sec.name.substr(0,sec.name.find('\0'));
        sec.virtualAddress=secHeader[i].VirtualAddress;
        sec.rawSize=secHeader[i].SizeOfRawData;
        sec.rawOffset=secHeader[i].PointerToRawData;
        sec.characteristics=secHeader[i].Characteristics;
        sec.entropy=0.0;
        pe.sections.push_back(sec);    
    }
    return pe;
}


void unloadPE(PEInfo& pe){
    if(pe.base&&pe.base!=MAP_FAILED) munmap(pe.base, pe.fileSize);
    if(pe.fd>=0) close(pe.fd);
}

uint8_t* rvaToPtr(const PEInfo& pe, uint32_t rva) {
    for (auto& sec : pe.sections) {
        if (rva>=sec.virtualAddress && rva < sec.virtualAddress + sec.rawSize)
           return pe.base + sec.rawOffset + (rva-sec.virtualAddress);
    }
    return nullptr;
}


