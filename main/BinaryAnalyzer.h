#ifndef H_BINAHYANALYZEH_H
#define H_BINAHYANALYZEH_H

#include <stdint.h>
#include "Binary.h"
#include "General.h"
#include "Section.h"

namespace holodec {

	struct BinaryAnalyzer {
		HString name;
		HString desc;

		BinaryAnalyzer (HString name, HString desc) : name (name), desc (desc) {}
		virtual ~BinaryAnalyzer() {}

		virtual bool canAnalyze(Data* data) = 0;

		virtual bool init (Data* data) = 0;
		virtual bool terminate() = 0;

		virtual Binary* getBinary () = 0;

		virtual void doSectionAnalysis() = 0;

		virtual void analyzeStrings() = 0;
		virtual void analyzeValues() = 0;
		virtual void analyzeFunctions() = 0;

		virtual void analyzeEntryPoint() = 0;

		virtual void analyzeAllSymbols() = 0;

	};

}

#endif // H_BINAHYANALYZEH_H
