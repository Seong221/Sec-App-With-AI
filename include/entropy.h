#pragma once
#include "pe_parser.h"

struct EntropyReport{
    std::vector<std::pair<std::string, double>> sectionEntropies;
    int score=0;
};

double shannonEntropy(const uint8_t* data, size_t size);
EntropyReport analyzeEntropy(PEInfo& pe);

