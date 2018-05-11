
#ifndef IRGEN_H
#define IRGEN_H

#include "General.h"
#include <stdio.h>
#include "Architecture.h"
#include "Function.h"
#include "IR.h"

namespace holodec {
	
	struct IRGenerator {
		Architecture* arch;

		bool parseFunction (Function* function);
	};
	
	struct IRParser {
		size_t index = 0;
		HString string;

		Architecture* arch;
		IRRepresentation* rep;
		
		std::map<HString, IRExpression> expressionmap;
		
		IRParser (Architecture* arch);

		char peek() {
			return string[static_cast<int>(index)];
		}
		char pop() {
			return string[static_cast<int>(index++)];
		}
		void consume (size_t count = 1) {
			index += count;
		}
		void pushback (size_t count = 1) {
			index -= count;
		}

		IRArgument parseIndex (IRArgument expr);
		int parseArguments (IRExpression* expr);
		IRArgument parseIRExpression();
		bool parseProcFlags(IRExpression* expr);
		bool parseArgFlags(IRArgument* arg);

		bool parseIdentifier (char *buffer, size_t buffersize);
		IRArgument parseBuiltin();
		IRArgument parseToken();
		bool parseCharacter (char character);
		void skipWhitespaces();
		bool parseStringIndex (IRExpression* expression);
		uint32_t parseNumberIndex ();
		bool parseNumber (int64_t* num);

		void printParseFailure (const char*);

		void parse (IRRepresentation* rep);
	};
}

#endif //IRGEN_H