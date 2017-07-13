
#include "HoloSSA.h"
#include <assert.h>

bool holodec::holossa::HSSAGenerator::parseFunction (HFunction* function) {
	for (HBasicBlock& bb : function->basicblocks) {
		printf ("Basic Block ------------------------------\n");
		for (HInstruction& instr : bb.instructions) {
			holoir::HIRRepresentation& ir = instr.instrdef->il_string[instr.opcount];
			if (ir) {
				instr.print (arch);
				printf("Root: %d\n",ir.rootExpr);
				for (holoir::HIRExpression expr : ir.expressions) {
					if (expr.token == holoir::HIR_TOKEN_OP_ARG) {
						HInstArgument& arg = instr.operands[expr.mod.var_index - 1];
						switch (arg.type.type) {
						case H_LOCAL_TYPE_REGISTER:
							expr.token = holoir::HIR_TOKEN_REGISTER;
							expr.regacces = arg.reg;
							expr.mod.var_index = 0;
							break;
						case H_LOCAL_TYPE_STACK:
							expr.token = holoir::HIR_TOKEN_OP_STCK;
							expr.mod.var_index = arg.stackindex;
							break;
						case H_LOCAL_TYPE_MEM:
						//TODO
							expr.token = holoir::HIR_TOKEN_MEM;
							expr.mem.base = arg.mem.base;
							expr.mem.index = arg.mem.index;
							expr.mem.disp = arg.mem.disp;
							expr.mem.scale = arg.mem.scale;
							expr.mod.var_index = 0;
							break;
						case H_LOCAL_TYPE_IMM_SIGNED:
						case H_LOCAL_TYPE_IMM_UNSIGNED:
							expr.token = holoir::HIR_TOKEN_NUMBER;
							expr.value = arg.ival;
							expr.mod.var_index = 0;
						break;
						case H_LOCAL_TYPE_IMM_FLOAT:
							expr.token = holoir::HIR_TOKEN_FLOAT;
							expr.value = arg.fval;
							expr.mod.var_index = 0;
						break;
						}
					}
					expr.print (arch);
				}
			}
			//parseInstruction (&instr);
		}
	}
}
