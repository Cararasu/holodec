#ifndef HSSAASSIGNMENTSIMPLIFIER_H
#define HSSAASSIGNMENTSIMPLIFIER_H

#include "HSSATransformer.h"
namespace holodec {

	class HSSAAssignmentSimplifier : public HSSATransformer {

		virtual void doTransformation (HFunction* function);
	};

}

#endif // HSSAASSIGNMENTSIMPLIFIER_H
