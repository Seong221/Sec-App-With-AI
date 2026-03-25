#include "report_writer.h"
#include <iostream>
#include <iomanip>

void printReport(const PEInfo& pe,
                 const ImportReport& imp,
                 const StringReport& str,
                 const EntropyReport& ent) {
    int total=imp.score+str.score+ent.score;

    std::cout << "\n====== PE SANDBOX REPORT ======\n";
    std::cout << "Architecture : " << (pe.is64bit ? "x64" : "x86") << "\n";
    std::cout << "Sections     : " << pe.sections.size() << "\n\n";

    std::cout << "--Entropy per section --\n";
    for (auto& [name, H] : ent.sectionEntropies)
        std::cout << " " <<std::setw(10) << std::left << name
                  << std::fixed << std::setprecision(4) << H
                  << (H > 7.2 ? " [HIGH-possible packing]"  :  "") << "\n";

    std::cout << "\n --Suspicious APIs --\n";
    for (auto& api : imp.suspiciousApis)
        std::cout << "  [!]" << api << "\n";
    if (imp.suspiciousApis.empty()) std::cout << " None found\n";

    std::cout << "\n-- Network indicators --\n";
    for (auto& u: str.urls) std::cout << " [URL] "<< u << "\n";
    for (auto& ip: str.ips) std::cout << " [IP] " << ip << "\n";
    if(str.urls.empty() && str.ips.empty()) std::cout << " None found\n";

    std::cout << "\n--Registry keys --\n";
    for(auto& r : str.registryKeys) std::cout << "  " << r << "\n";
    if(str.registryKeys.empty()) std::cout << " None found\n";

    std::cout << "\n=========================\n";
    std::cout << "RISK SCORE: " << total << " / 100\n";
    std::cout << "Imports: " << imp.score << "\n";
    std::cout << " Strings: " << str.score << "\n";
    std::cout << " Entropy: " << ent.score << "\n";
    std::cout << "==========================\n\n"; 
    }
