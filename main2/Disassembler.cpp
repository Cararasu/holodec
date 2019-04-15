
#include "pch.h"
#include "Disassembler.h"


namespace holodec {


	//Is called once at the beginning
	void Disassembler::init() {

	}
	//Is called once at the end
	void Disassembler::finit() {

	}

	//Is called once for each Binary and sets the context
	void Disassembler::prepare(DecompContext* context) {
		this->context = *context;
	}
	//Is called when disassembly is finished for this context
	void Disassembler::finish() {

	}


	void Disassembler::post_instruction(Instruction* instr) {

	}
	void Disassembler::register_disassemble_location(u64 location) {

	}

	void Disassembler::disassemble_instructions(u64 location) {

	}


}