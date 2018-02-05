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
		holodec::Binary* binary;

		BinaryAnalyzer (HString name, HString desc) : name (name), desc (desc) {}
		virtual ~BinaryAnalyzer() {}

		virtual bool canAnalyze(Data* data) = 0;

		virtual bool init (Data* data) = 0;
		virtual bool terminate() = 0;

		holodec::Binary* getBinary() {
			return binary;
		}

	};

}

#endif // H_BINAHYANALYZEH_H
