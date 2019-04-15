#pragma once

#include "Instruction.h"
#include "Architecture.h"

namespace holodec {

	struct Disassembler {
		DecompContext context;

		//Is called once at the beginning
		virtual void init();
		//Is called once at the end
		virtual void finit();

		//Is called once for each Binary and sets the context
		virtual void prepare(DecompContext* context);
		//Is called when disassembly is finished for this context
		virtual void finish();


		void post_instruction(Instruction* instr);
		void register_disassemble_location(u64 location);

		virtual void disassemble_instructions(u64 location) = 0;

	};
}

