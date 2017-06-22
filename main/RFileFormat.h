#ifndef RFILEFORMAT_H
#define RFILEFORMAT_H

#include <functional>
#include "RString.h"
#include "RData.h"
#include "RBinaryAnalyzer.h"

namespace holodec {

	struct RFileFormat {
		RString name;
		RString desc;

		RList<std::function<RBinaryAnalyzer*(RData*, RString)>> binaryanalyzerfactory;

		RBinaryAnalyzer* createBinaryAnalyzer (RData* data,RString name = 0) {
			for (std::function<RBinaryAnalyzer*(RData*, RString)>& fac : binaryanalyzerfactory){
				RBinaryAnalyzer* analyzer = fac(data,name);
				if(analyzer)
					return analyzer;
					
			}
			return 0;
		}
	};

}

#endif // RFILEFORMAT_H
