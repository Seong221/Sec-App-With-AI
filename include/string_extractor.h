#pragma once
#include "pe_parser.h"
#include <string>
#include <vector>

struct StringReport{
    std::vector<std::string> strings;
    std::vector<std::string> urls;
    std::vector<std::string> ips;
    std::vector<std::string> registryKeys;
    int score=0;
};

StringReport extractStrings(const PEInfo& pe, int minLen=4);

