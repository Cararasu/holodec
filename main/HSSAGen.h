
#include "HGeneral.h"
#include <stdio.h>
#include "HArchitecture.h"
#include "HFunction.h"

namespace holodec {
	
	struct HSSAGenerator {
		HArchitecture* arch;

		bool parseFunction (HFunction* function);
	};
}
