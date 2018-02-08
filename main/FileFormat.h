#ifndef HFILEFOHMAT_H
#define HFILEFOHMAT_H

#include <functional>
#include "HString.h"
#include "Data.h"
#include "BinaryAnalyzer.h"

namespace holodec {

	struct FileFormat {
		HString name;
		HString desc;

		HList<std::function<BinaryAnalyzer*(File*, HString)>> binaryanalyzerfactory;

		BinaryAnalyzer* createBinaryAnalyzer (File* file, HString name) {
			for (std::function<BinaryAnalyzer*(File*, HString)>& fac : binaryanalyzerfactory){
				BinaryAnalyzer* analyzer = fac(file,name);
				if(analyzer)
					return analyzer;
					
			}
			return 0;
		}
	};

}

#endif // HFILEFOHMAT_H
