#include "pe_parser.h"
#include "import_analyzer.h"
#include "string_extractor.h"
#include "entropy.h"
#include "report_writer.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc<2){
        std::cerr << "Usage: pesandbox <path-to-pe-file>\n";
        return 1;
    }
    try {
        PEInfo pe = loadPE(argv[1]);
        auto imp=analyzeImports(pe);
        auto str = extractStrings(pe);
        auto ent = analyzeEntropy(pe);
        printReport(pe, imp, str, ent);
        unloadPE(pe);
    }catch(std::exception& e) {
        std::cerr << "Error: " <<e.what() << "\n";
        return 1;
    }
    return 0;
}


