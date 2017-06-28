#ifndef HFILEFOHMAT_H
#define HFILEFOHMAT_H

#include <functional>
#include "HString.h"
#include "HData.h"
#include "HBinaryAnalyzer.h"

namespace holodec {

	struct HFileFormat {
		HString name;
		HString desc;

		HList<std::function<HBinaryAnalyzer*(HData*, HString)>> binaryanalyzerfactory;

		HBinaryAnalyzer* createBinaryAnalyzer (HData* data,HString name = 0) {
			for (std::function<HBinaryAnalyzer*(HData*, HString)>& fac : binaryanalyzerfactory){
				HBinaryAnalyzer* analyzer = fac(data,name);
				if(analyzer)
					return analyzer;
					
			}
			return 0;
		}
	};

}

#endif // HFILEFOHMAT_H
