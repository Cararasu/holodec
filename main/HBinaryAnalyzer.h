#ifndef H_BINAHYANALYZEH_H
#define H_BINAHYANALYZEH_H

#include <stdint.h>
#include "HBinary.h"
#include "HGeneral.h"
#include "HSection.h"

namespace holodec {

	struct HBinaryAnalyzer {
		HString name;
		HString desc;

		HBinaryAnalyzer (HString name, HString desc) : name (name), desc (desc) {}
		virtual ~HBinaryAnalyzer() {}

		virtual bool canAnalyze(HData* data) = 0;

		virtual bool init (HData* data) = 0;
		virtual bool terminate() = 0;

		virtual HBinary* getBinary () = 0;

		virtual void doSectionAnalysis() = 0;

		virtual void analyzeStrings() = 0;
		virtual void analyzeValues() = 0;
		virtual void analyzeFunctions() = 0;

		virtual void analyzeEntryPoint() = 0;

		virtual void analyzeAllSymbols() = 0;

	};

}

#endif // H_BINAHYANALYZEH_H
