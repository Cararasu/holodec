

#include "Architecture.h"
#include "Main.h"

extern "C" {
#include "CHolodec.h"

	void holodec_init (void) {
		holodec::Main::initMain();
	}
	HArchitecture* holodec_get_arch (uint64_t index) {
		return reinterpret_cast<HArchitecture*> (holodec::Main::g_main->architectures[index]);
	}
	HArchitecture* holodec_get_arch_by_name (const char* name) {
		return reinterpret_cast<HArchitecture*> (holodec::Main::g_main->getArchitecture (name));
	}
	uint64_t holodec_get_archcount (void) {
		return holodec::Main::g_main->architectures.size();
	}

	const char* arch_get_name (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->name.cstr();
	}
	const char* arch_get_description (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->desc.cstr();
	}
	uint64_t arch_get_bitbase (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->bitbase;
	}
	uint64_t arch_get_wordbase (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->wordbase;
	}

	HRegister* arch_get_register (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HRegister*> (&reinterpret_cast<holodec::Architecture*> (arch)->registers.list[index]);
	}
	HRegister* arch_get_register_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HRegister*> (&reinterpret_cast<holodec::Architecture*> (arch)->registers[index]);
	}
	uint64_t arch_get_regcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->registers.size();
	}

	HStack* arch_get_stack (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HStack*> (&reinterpret_cast<holodec::Architecture*> (arch)->stacks.list[index]);
	}
	HStack* arch_get_stack_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HStack*> (&reinterpret_cast<holodec::Architecture*> (arch)->stacks[index]);
	}
	uint64_t arch_get_stackcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->stacks.size();
	}

	HCallingConvention* arch_get_cc (HArchitecture* arch, uint64_t index) {
		return reinterpret_cast<HCallingConvention*> (&reinterpret_cast<holodec::Architecture*> (arch)->callingconventions.list[index]);
	}
	HCallingConvention* arch_get_cc_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HCallingConvention*> (&reinterpret_cast<holodec::Architecture*> (arch)->callingconventions[index]);
	}
	uint64_t arch_get_cccount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->callingconventions.size();
	}

	HInstrDefinition* arch_get_instrdef (HArchitecture* arch, uint64_t index) {
		holodec::Architecture* a = reinterpret_cast<holodec::Architecture*> (arch);
		return reinterpret_cast<HInstrDefinition*> (&a->instrdefs[a->instrIds[index]]);
	}
	HInstrDefinition* arch_get_instrdef_by_id (HArchitecture* arch, uint32_t index) {
		return reinterpret_cast<HInstrDefinition*> (&reinterpret_cast<holodec::Architecture*> (arch)->instrdefs[index]);
	}
	uint64_t arch_get_instrdefcount (HArchitecture* arch) {
		return reinterpret_cast<holodec::Architecture*> (arch)->instrdefs.size();
	}
}
