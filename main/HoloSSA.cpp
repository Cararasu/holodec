
#include "HoloSSA.h"
#include <assert.h>

bool holodec::holossa::HSSAGenerator::parseFunction ( HFunction* function ) {
	for ( HBasicBlock& bb : function->basicblocks ) {
		for ( HInstruction& instr : bb.instructions ) {
			parseInstruction ( &instr );
		}
	}
}

bool holodec::holossa::HSSAGenerator::parseInstruction ( HInstruction* instr ) {
	printf ( "%s ",instr->instrdef->mnemonics.cstr() );
	if ( !instr->instrdef->il_string[instr->opcount] ) {
		printf ( "Big Error\n" );
		return false;
	}
	for ( int i = 0; instr->operands[i].type.type; i++ ) {
		instr->operands[i].print ( this->arch );
		printf ( " " );
	}
	printf ( "\n---------------------------------\n" );
	return parseExpression ( instr->operands, instr->instrdef->il_string[instr->opcount].expression ).type != HSSAIR_TYPE_INVALID;
}

holodec::holossa::HSSAParsedExpression holodec::holossa::HSSAGenerator::parseExpression ( HInstArgument* arguments, holoir::HIRExpression* expression ) {
	if ( !expression )
		return {HSSAIR_TYPE_INVALID};
	HSSAParsedExpression parsedExpr {HSSAIR_TYPE_INVALID};
	switch ( expression->token ) {
	case holodec::holoir::HIR_TOKEN_INVALID:
		printf ( "Error\n" );
		break;
	case holodec::holoir::HIR_TOKEN_FLAG_C:
	case holodec::holoir::HIR_TOKEN_FLAG_A:
	case holodec::holoir::HIR_TOKEN_FLAG_P:
	case holodec::holoir::HIR_TOKEN_FLAG_O:
	case holodec::holoir::HIR_TOKEN_FLAG_Z:
	case holodec::holoir::HIR_TOKEN_FLAG_S:
		break;
		//Variables
	case holodec::holoir::HIR_TOKEN_OP_ARG: {
		HInstArgument& instArg = arguments[expression->mod.var_index - 1];
		switch ( instArg.type.type ) {
		case H_LOCAL_TYPE_REGISTER:
			parsedExpr.type = HSSAIR_TYPE_REGISTER;
			break;
		case H_LOCAL_TYPE_STACK:
			parsedExpr.type = HSSAIR_TYPE_STACK;
			break;
		case H_LOCAL_TYPE_MEM:
			parsedExpr.type = HSSAIR_TYPE_MEM;
			break;
		case H_LOCAL_TYPE_IMM_SIGNED:
		case H_LOCAL_TYPE_IMM_UNSIGNED:
			parsedExpr.type = HSSAIR_TYPE_VALUE;
			parsedExpr.value = instArg.ival;
			break;
		case H_LOCAL_TYPE_IMM_FLOAT:
			parsedExpr.type = HSSAIR_TYPE_RESULT;
			break;
		}
		if ( parsedExpr.type == HSSAIR_TYPE_RESULT || parsedExpr.type == HSSAIR_TYPE_MEM ) {
			printf ( "%d = ",parsedExpr.resultid );
			instArg.print ( this->arch );
			printf ( "\n" );
			parsedExpr.resultid = gen_expr.next();
		}

		break;
	}
	case holodec::holoir::HIR_TOKEN_OP_STCK:
	case holodec::holoir::HIR_TOKEN_OP_TMP:
		break;

	case holodec::holoir::HIR_TOKEN_NUMBER:
		parsedExpr.type = HSSAIR_TYPE_VALUE;
		parsedExpr.value = expression->value;
		break;

	case holodec::holoir::HIR_TOKEN_VALUE: {
		assert ( expression->subexpressions.size() == 1 );
		parsedExpr = parseExpression ( arguments,expression->subexpressions[0] );
		if ( parsedExpr.type == HSSAIR_TYPE_MEM ) {
			parsedExpr.type = HSSAIR_TYPE_RESULT;
		}
	}

	//Call - Return
	case holodec::holoir::HIR_TOKEN_OP_JMP:
	case holodec::holoir::HIR_TOKEN_OP_CALL:
	case holodec::holoir::HIR_TOKEN_OP_RET:
	case holodec::holoir::HIR_TOKEN_OP_SYSCALL:
	case holodec::holoir::HIR_TOKEN_OP_TRAP:
		break;
		//Misc
	case holodec::holoir::HIR_TOKEN_OP_ASSIGN: {

		assert ( expression->subexpressions.size() == 2 );
		HSSAParsedExpression exprs[expression->subexpressions.size()];
		int i = 0;
		for ( holoir::HIRExpression* expr : expression->subexpressions ) {
			exprs[i] = parseExpression ( arguments,expr );
			i++;
		}
		if ( exprs[0].type == HSSAIR_TYPE_MEM ) {
			printf ( "store (%d,%d)\n",exprs[0].resultid,exprs[1].resultid );
			switch(exprs[1].type){
			case HSSAIR_TYPE_INVALID:
			case HSSAIR_TYPE_VALUE:
			case HSSAIR_TYPE_RESULT:
			case HSSAIR_TYPE_REGISTER:
			case HSSAIR_TYPE_ARGUMENT:
			case HSSAIR_TYPE_STACK:
			case HSSAIR_TYPE_TEMP:
			case HSSAIR_TYPE_MEM:
			case HSSAIR_TYPE_AGGREGATION:
			}
		} else {
			printf ( "wuut? %d = %d\n",exprs[0].resultid,exprs[1].resultid );
		}
		parsedExpr.type = HSSAIR_TYPE_RESULT;
		parsedExpr.resultid = exprs[0].resultid;
	}

	case holodec::holoir::HIR_TOKEN_OP_SIZE:
	case holodec::holoir::HIR_TOKEN_OP_POPCNT:
	case holodec::holoir::HIR_TOKEN_OP_LOOP:
	case holodec::holoir::HIR_TOKEN_OP_IF:
	case holodec::holoir::HIR_TOKEN_OP_REC:
	case holodec::holoir::HIR_TOKEN_OP_EXTEND:
	case holodec::holoir::HIR_TOKEN_OP_SEXTEND:
		break;
		//Arithmetic
	case holodec::holoir::HIR_TOKEN_OP_ADD: {
		assert ( expression->subexpressions.size() >= 2 );
		HSSAParsedExpression exprs[expression->subexpressions.size()];
		int i = 0;
		for ( holoir::HIRExpression* expr : expression->subexpressions ) {
			exprs[i] = parseExpression ( arguments,expr );
			i++;
		}
		HId id;
		for ( int j = 1; j < i; j++ ) {
			id = gen_expr.next();
			printf ( "%d = %d + %d\n",id, exprs[i-1].resultid,exprs[i].resultid );
		}
	}
	break;
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

	parseExpression ( arguments,expression->sequence );
	return parsedExpr;
}
