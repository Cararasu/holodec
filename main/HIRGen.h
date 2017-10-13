
#ifndef HIRGEN_H
#define HIRGEN_H

#include "HGeneral.h"
#include <stdio.h>
#include "HArchitecture.h"
#include "HFunction.h"
#include "HIR.h"

namespace holodec {
	
	struct HIRGenerator {
		HArchitecture* arch;

		bool parseFunction (HFunction* function);
	};
	
	struct HIRParser {
		size_t index;
		HString string;

		HArchitecture* arch;
		HIRRepresentation* rep;

		HIRParser (HArchitecture* arch) : arch (arch) {}

		char peek() {
			return string[index];
		}
		char pop() {
			return string[index++];
		}
		void consume (size_t count = 1) {
			index += count;
		}
		void pushback (size_t count = 1) {
			index -= count;
		}

		HIRArgument parseIndex (HIRArgument expr);
		int parseArguments (HIRExpression* expr);
		HIRArgument parseIRExpression();

		bool parseIdentifier (char *buffer, size_t buffersize);
		HIRArgument parseBuiltin();
		HIRArgument parseToken();
		bool parseCharacter (char character);
		void skipWhitespaces();
		bool parseStringIndex (HIRExpression* expression);
		int64_t parseNumberIndex ();
		bool parseNumber (int64_t* num);

		void printParseFailure (const char*);

		void parse (HIRRepresentation* rep);
	};
}

#endif //HIRGEN_H