#include "PeepholeOptimizer.h"


#include <fstream>
#include <cctype>
#include "SSAPeepholeOptimizer.h"

namespace holodec {

	void parseComment (std::ifstream* file) {
		char c;
		while (file->get (c).good() && c != '\n');
	}
	void parseWhitespaces (std::ifstream* file) {
		char c;
		do {
			while (file->get (c).good() && (c == ' ' || c == '\t' || c == '\n'));
			if (c == '/' && file->peek() == '/') {
				file->get (c);
				parseComment (file);
			} else break;
		} while (true);
		file->putback (c);
	}
	size_t parseIdentifier (std::ifstream* file, char* buffer, size_t buffersize) {
		parseWhitespaces (file);
		if (!file->good()) {
			buffer[0] = '\0';
			return 0;
		}
		char c;
		size_t read = 0;
		while (true) {
			if (file->get (c).good() && (isalnum (c) || c == '-' || c == '.') && read < buffersize) {
				buffer[read] = c;
				read++;
			} else {
				file->putback (c);
				buffer[read] = '\0';
				return read;
			}
		}
	}
	bool parseSingleChar (std::ifstream* file, char matchC) {
		parseWhitespaces (file);
		char c;
		if (!file->get (c).good() || c != matchC) {
			file->putback (c);
			return false;
		}
		return true;
	}
	bool parseKeyValue (std::ifstream* file, char* keyBuffer, size_t keyBuffersize, char* valueBuffer, size_t valueBuffersize) {
		return parseIdentifier (file, keyBuffer, keyBuffersize) && parseSingleChar (file, '=') && parseIdentifier (file, valueBuffer, valueBuffersize);
	}

	std::vector<std::pair<HString, MatchRuleType>> typerules = {
		{"type", MATCHRULE_TYPE},
		{"builtin", MATCHRULE_BUILTIN},
		{"location", MATCHRULE_LOCATION},
		{"argtype", MATCHRULE_ARGUMENTTYPE},
		{"argvalue", MATCHRULE_ARGUMENTVALUE},
	};
	std::vector<std::pair<HString, SSAExprType>> ssatypes = {
		{"label", SSA_EXPR_LABEL},
		{"undef", SSA_EXPR_UNDEF},
		{"nop", SSA_EXPR_NOP},
		{"op", SSA_EXPR_OP},
		{"loadaddr", SSA_EXPR_LOADADDR},
		{"flag", SSA_EXPR_FLAG},
		{"builtin", SSA_EXPR_BUILTIN},
		{"extend", SSA_EXPR_EXTEND},
		{"split", SSA_EXPR_SPLIT},
		{"updatepart", SSA_EXPR_UPDATEPART},
		{"append", SSA_EXPR_APPEND},
		{"cast", SSA_EXPR_CAST},
		{"input", SSA_EXPR_INPUT},
		{"output", SSA_EXPR_OUTPUT},
		{"call", SSA_EXPR_CALL},
		{"return", SSA_EXPR_RETURN},
		{"syscall", SSA_EXPR_SYSCALL},
		{"phi", SSA_EXPR_PHI},
		{"assign", SSA_EXPR_ASSIGN},
		{"jmp", SSA_EXPR_JMP},
		{"cjmp", SSA_EXPR_CJMP},
		{"multibr", SSA_EXPR_MULTIBR},
		{"push", SSA_EXPR_PUSH},
		{"pop", SSA_EXPR_POP},
		{"store", SSA_EXPR_STORE},
		{"load", SSA_EXPR_LOAD},
	};
	std::vector<std::pair<HString, SSAOpType>> ssaoptypes = {
		{"add", H_OP_ADD},
		{"sub", H_OP_SUB},
		{"mul", H_OP_MUL},
		{"div", H_OP_DIV},
		{"mod", H_OP_MOD},
		{"and", H_OP_AND},
		{"or", H_OP_OR},
		{"xor", H_OP_XOR},
		{"not", H_OP_NOT},
		{"eq", H_OP_EQ},
		{"ne", H_OP_NE},
		{"l", H_OP_L},
		{"le", H_OP_LE},
		{"g", H_OP_G},
		{"ge", H_OP_GE},
		{"band", H_OP_BAND},
		{"bor", H_OP_BOR},
		{"bxor", H_OP_BXOR},
		{"bnot", H_OP_BNOT},
		{"shr", H_OP_SHR},
		{"shl", H_OP_SHL},
		{"sar", H_OP_SAR},
		{"sal", H_OP_SAL},
		{"ror", H_OP_ROR},
		{"rol", H_OP_ROL}
	};
	std::vector<std::pair<HString, std::function<bool (MatchRule*, const char*) >>> ruleparams = {
		{
			"type", [] (MatchRule * rule, const char* value) {
				HString valuestr = value;
				for (auto& p : ssatypes) {
					if (p.first == valuestr) {
						rule->type.type = p.second;
						return true;
					}
				}
				return false;
			}
		}, {
			"op", [] (MatchRule * rule, const char* value) {
				HString valuestr = value;
				for (auto& p : ssaoptypes) {
					if (p.first == valuestr) {
						rule->type.opType = p.second;
						return true;
					}
				}
				return false;
			}
		}
	};

	void* parseMatchRule (std::ifstream* file) {
		char buffer[100];
		size_t parsedchars = parseIdentifier (file, buffer, 100);
		MatchRule matchRule;
		HString rulename = buffer;
		for (auto& p : typerules) {
			if (p.first == rulename) {
				matchRule.matchRuleType = p.second;
			}
		}
		if (!matchRule.matchRuleType)
			return nullptr;
		printf ("Rule %s\n", buffer);
		if (!parseSingleChar (file, '(')) {
			return nullptr;
		}
		do {
			char keyBuffer[100];
			char valueBuffer[100];
			if (!parseKeyValue (file, keyBuffer, 100, valueBuffer, 100)) {
				printf ("Rule %s\n", buffer);
				return nullptr;
			}
			HString keyname = buffer;
			for (auto& p : ruleparams) {
				if (p.first == keyname) {
					p.second (&matchRule, valueBuffer);
				}
			}
			if (strcmp (keyBuffer, "flag") == 0) {

			} else if (strcmp (keyBuffer, "size") == 0) {

			} else if (strcmp (keyBuffer, "foundIndex") == 0) {

			} else if (strcmp (keyBuffer, "foundArgIndex") == 0) {

			} else if (strcmp (keyBuffer, "argIndex") == 0) {

			} else if (strcmp (keyBuffer, "index") == 0) {

			} else if (strcmp (keyBuffer, "uval") == 0) {

			} else if (strcmp (keyBuffer, "sval") == 0) {

			} else if (strcmp (keyBuffer, "fval") == 0) {

			} else if (strcmp (keyBuffer, "name") == 0) {

			} else if (strcmp (keyBuffer, "reg") == 0) {

			} else if (strcmp (keyBuffer, "stack") == 0) {

			} else if (strcmp (keyBuffer, "mem") == 0) {

			} else {
				printf ("Invalid Key %s\n", keyBuffer);
			}

		} while (parseSingleChar (file, ','));
		if (!parseSingleChar (file, ')')) {
			return nullptr;
		}

		return (void*) 1;
	}


	void* parseMatcher (std::ifstream* file) {
		char buffer[100];
		size_t parsedchars = parseIdentifier (file, buffer, 100);
		if (parsedchars == 7 && strcmp (buffer, "matcher") == 0) {
			if (!parseSingleChar (file, '{')) {
				return nullptr;
			}
			while (parsedchars = parseIdentifier (file, buffer, 100)) {
				if (parsedchars == 5 && strcmp (buffer, "rules") == 0) {
					printf ("Rules\n");
					if (!parseSingleChar (file, '{')) {
						return nullptr;
					}
					while (parseMatchRule (file));
					if (!parseSingleChar (file, '}')) {
						return nullptr;
					}
				} else if (parsedchars == 10 && strcmp (buffer, "submatches") == 0) {
					printf ("Submatches\n");
					if (!parseSingleChar (file, '{')) {
						return nullptr;
					}
					if (!parseSingleChar (file, '}')) {
						return nullptr;
					}
				} else if (parsedchars == 7 && strcmp (buffer, "actions") == 0) {
					printf ("Actions\n");
					if (!parseSingleChar (file, '{')) {
						return nullptr;
					}
					if (!parseSingleChar (file, '}')) {
						return nullptr;
					}
				} else {
					printf ("End");
					return nullptr;
				}
			}
			if (!parseSingleChar (file, '}')) {
				return nullptr;
			}
		}

	}


	PeepholeOptimizer* parsePhOptimizer (const char* filename, Architecture* arch) {
		std::ifstream file (filename);
		if (!file.good())
			return nullptr;

		parseMatcher (&file);

		return nullptr;
	}

}
