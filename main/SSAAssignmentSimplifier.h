#ifndef SSAASSIGNMENTSIMPLIFIER_H
#define SSAASSIGNMENTSIMPLIFIER_H

#include "SSATransformer.h"
namespace holodec {

	class SSAAssignmentSimplifier : public SSATransformer {

		virtual void doTransformation (Function* function);
	};

}

#endif // SSAASSIGNMENTSIMPLIFIER_H
