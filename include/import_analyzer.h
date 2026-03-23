#pragma once
#include "pe_parser.h"
#include <string>
#include <vector>
#include <map>

struct ImportEntry {
    std::string dll;
    std::vector<std::string> functions;
};

struct ImportReport{
    std::vector<ImportEntry> imports;
    std::vector<std::string> suspiciousApis;
    int score=0;
};

ImportReport analyzeImports(const PEInfo& pe);

