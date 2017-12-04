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

		HList<std::function<BinaryAnalyzer*(Data*, HString)>> binaryanalyzerfactory;

		BinaryAnalyzer* createBinaryAnalyzer (Data* data,HString name) {
			for (std::function<BinaryAnalyzer*(Data*, HString)>& fac : binaryanalyzerfactory){
				BinaryAnalyzer* analyzer = fac(data,name);
				if(analyzer)
					return analyzer;
					
			}
			return 0;
		}
	};

}

#endif // HFILEFOHMAT_H
