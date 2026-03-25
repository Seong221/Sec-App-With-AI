#include "entropy.h"
#include <cmath>

double shannonEntropy(const uint8_t* data, size_t size) {
    if (!size) return 0.0;
    int freq[256] = {};
    for (size_t i=0; i<size; i++) freq[data[i]]++;
    double H = 0.0;
    for(int i=0; i<256; i++) {
        if(!freq[i])continue;
        double p = (double)freq[i]/size;
        H-=p*log2(p);
    }
    return H;
}

EntropyReport analyzeEntropy(PEInfo& pe) {
    EntropyReport report;
    for(auto& sec:pe.sections) {
        if(!sec.rawSize)continue;
        double H=shannonEntropy(pe.base + sec.rawOffset, sec.rawSize);
        sec.entropy=H;
        report.sectionEntropies.push_back({sec.name, H});
        if(H>7.2) report.score +=15;
    }
    return report;
}


