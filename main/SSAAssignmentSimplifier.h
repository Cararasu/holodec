#ifndef SSAASSIGNMENTSIMPLIFIER_H
#define SSAASSIGNMENTSIMPLIFIER_H

#include "SSATransformer.h"
namespace holodec {

	class SSAAssignmentSimplifier : public SSATransformer {

		virtual void doTransformation (Binary* binary, Function* function);
	};

}

#endif // SSAASSIGNMENTSIMPLIFIER_H
