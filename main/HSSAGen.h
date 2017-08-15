
#include "HGeneral.h"
#include <stdio.h>
#include "HArchitecture.h"
#include "HFunction.h"

namespace holodec {
	
	struct HSSAGenerator {
		HArchitecture* arch;

		bool parseFunction (HFunction* function);
	};
	
	struct HSSAParser {
		size_t index;
		HString string;

		HArchitecture* arch;
		HIRRepresentation* rep;
		//Arguments
		//Stack
		//Temp

		HSSAParser (HArchitecture* arch) : arch (arch) {}

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

		HSSAArg parseIndex (HSSAArg* expr);
		int parseArguments (HSSAExpression* expr);
		HSSAArg parseExpression();

		bool parseIdentifier (char *buffer, size_t buffersize);
		HSSAArg parseBuiltin();
		HSSAArg parseToken();
		bool parseCharacter (char character);
		void skipWhitespaces();
		bool parseStringIndex (HSSAArg* expr);
		int64_t parseNumberIndex ();
		bool parseNumber (int64_t* num);

		void printParseFailure (const char*);

		void parse (HIRRepresentation* rep);
	};
}
