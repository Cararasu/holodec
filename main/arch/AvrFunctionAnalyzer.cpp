
#include "AvrFunctionAnalyzer.h"
#include "../Binary.h"

namespace holoavr{

	AVRFunctionAnalyzer::AVRFunctionAnalyzer(Architecture* arch): FunctionAnalyzer(arch) {

	}
	AVRFunctionAnalyzer::~AVRFunctionAnalyzer() {

	}

	bool AVRFunctionAnalyzer::canAnalyze(Binary* binary) {
		return holodec::caseCmpHString("avr", binary->arch.name);
	}

	bool AVRFunctionAnalyzer::init(Binary* binary) {
		this->binary = binary;



		return true;
	}
	bool AVRFunctionAnalyzer::terminate() {
		return true;
	}

	bool AVRFunctionAnalyzer::analyzeInsts(size_t addr) {
		printf("Disassemble at position %d\n", addr);

		printf("0x%x\n", *binary->data->get<uint8_t>(0));

		return true;
	}

}