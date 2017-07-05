
#include "HoloSSA.h"

bool holodec::holossa::HSSAGenerator::parseFunction(HFunction* function){
	for(HBasicBlock& bb : function->basicblocks){
		for(HInstruction& instr : bb.instructions){
			parseInstruction(&instr);
		}
	}
}

bool holodec::holossa::HSSAGenerator::parseInstruction(HInstruction* instr){
	printf("%s ",instr->instrdef->mnemonics.cstr());
	if(!instr->instrdef->il_string[instr->opcount]){
		printf("Big Error\n");
		return false;
	}
	for (int i = 0;instr->operands[i].type.type;i++){
		instr->operands[i].print();
		printf(" ");
	}
	printf("\n");
	return parseExpression(instr->operands, instr->instrdef->il_string[instr->opcount].expression);
}

holodec::HId holodec::holossa::HSSAGenerator::parseExpression(HInstArgument* arguments, holoir::HIRExpression* expression){
	if(!expression)
		return true;
	HId id = gen_expr.next();
	switch(expression->token){
			case holodec::holoir::HIR_TOKEN_INVALID:
				printf("Error\n");
				break;
			case holodec::holoir::HIR_TOKEN_FLAG_C:
			case holodec::holoir::HIR_TOKEN_FLAG_A:
			case holodec::holoir::HIR_TOKEN_FLAG_P:
			case holodec::holoir::HIR_TOKEN_FLAG_O:
			case holodec::holoir::HIR_TOKEN_FLAG_Z:
			case holodec::holoir::HIR_TOKEN_FLAG_S:
				return id;

			//Variables
			case holodec::holoir::HIR_TOKEN_OP_ARG:
				printf("Arg: %d\n",expression->mod.var_index);
				printf("%d = ",id);
				arguments[expression->mod.var_index - 1].print();
				printf("\n");
				return id;
			case holodec::holoir::HIR_TOKEN_OP_STCK:
			case holodec::holoir::HIR_TOKEN_OP_TMP:
				break;

			case holodec::holoir::HIR_TOKEN_NUMBER:
				printf("Num:\n");
				printf("%d = 0x%x\n",id,expression->value);
				return id;

			//Call - Return
			case holodec::holoir::HIR_TOKEN_OP_JMP:
			case holodec::holoir::HIR_TOKEN_OP_CALL:
			case holodec::holoir::HIR_TOKEN_OP_RET:
			case holodec::holoir::HIR_TOKEN_OP_SYSCALL:
			case holodec::holoir::HIR_TOKEN_OP_TRAP:
			break;
			//Misc
			case holodec::holoir::HIR_TOKEN_OP_ASSIGN:{
				
				if(expression->subexpressions.size() != 2)
					printf("WUUUSAPOIFHOAS\n");
				HId ids[expression->subexpressions.size()];
				int i = 0;
				for(holoir::HIRExpression* expr : expression->subexpressions){
					ids[i] = parseExpression(arguments,expr);
					i++;
				}
				printf("%d = %d\n",ids[0],ids[1]);
				return id;
			}

			case holodec::holoir::HIR_TOKEN_OP_SIZE:
			case holodec::holoir::HIR_TOKEN_OP_POPCNT:
			case holodec::holoir::HIR_TOKEN_OP_LOOP:
			case holodec::holoir::HIR_TOKEN_OP_IF:
			case holodec::holoir::HIR_TOKEN_OP_REC:
			case holodec::holoir::HIR_TOKEN_OP_EXTEND:
			case holodec::holoir::HIR_TOKEN_OP_SEXTEND:
			//Arithmetic
			case holodec::holoir::HIR_TOKEN_OP_ADD:
			case holodec::holoir::HIR_TOKEN_OP_SADD:
			case holodec::holoir::HIR_TOKEN_OP_FADD:
			case holodec::holoir::HIR_TOKEN_OP_SUB:
			case holodec::holoir::HIR_TOKEN_OP_SSUB:
			case holodec::holoir::HIR_TOKEN_OP_FSUB:
			case holodec::holoir::HIR_TOKEN_OP_MUL:
			case holodec::holoir::HIR_TOKEN_OP_SMUL:
			case holodec::holoir::HIR_TOKEN_OP_FMUL:
			case holodec::holoir::HIR_TOKEN_OP_DIV:
			case holodec::holoir::HIR_TOKEN_OP_SDIV:
			case holodec::holoir::HIR_TOKEN_OP_FDIV:
			//Memory
			case holodec::holoir::HIR_TOKEN_OP_STORE:
			case holodec::holoir::HIR_TOKEN_OP_LOAD:
			//Comparison
			case holodec::holoir::HIR_TOKEN_CMP_E:
			case holodec::holoir::HIR_TOKEN_CMP_NE:
			case holodec::holoir::HIR_TOKEN_CMP_L:
			case holodec::holoir::HIR_TOKEN_CMP_LE:
			case holodec::holoir::HIR_TOKEN_CMP_G:
			case holodec::holoir::HIR_TOKEN_CMP_GE:
			case holodec::holoir::HIR_TOKEN_CMP_NOT:
			//
			case holodec::holoir::HIR_TOKEN_OP_AND:
			case holodec::holoir::HIR_TOKEN_OP_OR:
			case holodec::holoir::HIR_TOKEN_OP_XOR:
			//Bit Operators
			case holodec::holoir::HIR_TOKEN_BINOP_AND:
			case holodec::holoir::HIR_TOKEN_BINOP_OR:
			case holodec::holoir::HIR_TOKEN_BINOP_XOR:
			case holodec::holoir::HIR_TOKEN_BINOP_NOT:
			//Shifts - Rotates
			case holodec::holoir::HIR_TOKEN_BINOP_SHR:
			case holodec::holoir::HIR_TOKEN_BINOP_SHL:
			case holodec::holoir::HIR_TOKEN_BINOP_SAR:
			case holodec::holoir::HIR_TOKEN_BINOP_SAL:
			case holodec::holoir::HIR_TOKEN_BINOP_ROR:
			case holodec::holoir::HIR_TOKEN_BINOP_ROL:
			//Casts
			case holodec::holoir::HIR_TOKEN_CAST_I2F:
			case holodec::holoir::HIR_TOKEN_CAST_F2I:

			case holodec::holoir::HIR_TOKEN_CUSTOM:
		break;
	}
	/*
	printf("%d\n",expression->token);
	for (int i = 0;arguments[i].type.type;i++){
		arguments[i].print();
		printf(" ");
	}
	printf("\n");*/
	
	for(holoir::HIRExpression* expr : expression->subexpressions){
		parseExpression(arguments,expr);
	}
}
