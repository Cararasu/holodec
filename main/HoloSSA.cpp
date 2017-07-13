
#include "HoloSSA.h"
#include <assert.h>

bool holodec::holossa::HSSAGenerator::parseFunction (HFunction* function) {
	for (HBasicBlock& bb : function->basicblocks) {
		for (HInstruction& instr : bb.instructions) {
			printf("Basic Block ------------------------------\n");
			//parseInstruction (&instr);
		}
	}
}