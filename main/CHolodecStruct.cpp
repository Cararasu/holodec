
extern "C"{
#include "CHolodec.h"
#include "CHolodecStruct.h"

	const struct Holodec_struct Holodec = {
		.init = holodec_init,
		.get_arch = holodec_get_arch,
		.get_arch_by_name = holodec_get_arch_by_name,
		.get_archcount = holodec_get_archcount,
		.arch = {
			.get_name = arch_get_name,
			.get_description = arch_get_description,
			.get_bitbase = arch_get_bitbase,
			.get_wordbase = arch_get_wordbase,

			.get_register = arch_get_register,
			.get_register_by_id = arch_get_register_by_id,
			.get_regcount = arch_get_regcount,

			.get_stack = arch_get_stack,
			.get_stack_by_id = arch_get_stack_by_id,
			.get_stackcount = arch_get_stackcount,

			.get_cc = arch_get_cc,
			.get_cc_by_id = arch_get_cc_by_id,
			.get_cccount = arch_get_cccount,

			.get_instrdef = arch_get_instrdef,
			.get_instrdef_by_id = arch_get_instrdef_by_id,
			.get_instrdefcount = arch_get_instrdefcount,
		}
	};

}