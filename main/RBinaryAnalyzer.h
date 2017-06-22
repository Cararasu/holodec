#ifndef R_BINARYANALYZER_H
#define R_BINARYANALYZER_H

#include <stdint.h>
#include "RBinary.h"
#include "RGeneral.h"
#include "RSection.h"

namespace radpp {

	struct RBinaryAnalyzer {
		RString name;
		RString desc;

		RBinaryAnalyzer (RString name, RString desc) : name (copyRString (name)), desc (copyRString (desc)) {}
		virtual ~RBinaryAnalyzer() {}

		virtual bool canAnalyze(RData* data) = 0;

		virtual bool init (RData* data) = 0;
		virtual bool terminate() = 0;

		virtual RBinary* getBinary () = 0;

		virtual void doSectionAnalysis() = 0;

		virtual void analyzeStrings() = 0;
		virtual void analyzeValues() = 0;
		virtual void analyzeFunctions() = 0;

		virtual void analyzeEntryPoint() = 0;

		virtual void analyzeAllSymbols() = 0;

	};

}

#endif // R_BINARYANALYZER_H
