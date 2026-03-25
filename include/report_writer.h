#pragma once
#include "import_analyzer.h"
#include "string_extractor.h"
#include "entropy.h"

void printReport(const PEInfo& pe,
                 const ImportReport& imp,
                 const StringReport& str,
                 const EntropyReport& ent);

