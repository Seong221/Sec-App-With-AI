#include "string_extractor.h"
#include <cctype>
#include <regex>

StringReport extractStrings(const PEInfo& pe, int minLen) {
    StringReport report;
    std::string current;

    for(size_t i=0; i<pe.fileSize; i++) {
        char c=pe.base[i];
        if(isprint((unsigned char)c)) {
            current+=c;
        }else{
            if((int)current.size()>=minLen)
                report.strings.push_back(current);
            current.clear();
        }
    }

    std::regex urlRe(R"(https?://[^\s]{6,})");
    std::regex ipRe(R"(\b\d{1,3}\.\d{1,3}\.d{1,3}\b)");
    std::regex regRe(R"(HKEY_[A-Z_]+\\[^\s]+)");

    for (auto& s:report.strings) {
        if (std::regex_search(s, urlRe)) { report.urls.push_back(s);        report.score+=8;}
        if (std::regex_search(s, ipRe))  { report.ips.push_back(s);         report.score+=8;}
        if (std::regex_search(s, regRe)) { report.registryKeys.push_back(s); report.score+=5;}
    }
    return report;
}
