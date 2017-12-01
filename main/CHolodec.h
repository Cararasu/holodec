
#ifndef CHOLODEC_H
#define CHOLODEC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define HOLODEC_PTR(type) typedef void* type;

HOLODEC_PTR (HArchitecture)
HOLODEC_PTR (HBinary)
HOLODEC_PTR (HFunction)
HOLODEC_PTR (HRegister)
HOLODEC_PTR (HStack)
HOLODEC_PTR (HMemory)
HOLODEC_PTR (HCallingConvention)
HOLODEC_PTR (HInstrDefinition)

HOLODEC_PTR (HSSARepresentation)
HOLODEC_PTR (HSSABB)
HOLODEC_PTR (HSSAExpression)
HOLODEC_PTR (HSSAArgument)

typedef uint32_t HId;

void holodec_init (void);
HArchitecture holodec_get_arch (uint64_t index);
HArchitecture holodec_get_arch_by_name (const char* name);
uint64_t holodec_get_archcount (void);

const char* arch_get_name (HArchitecture arch);
const char* arch_get_description (HArchitecture arch);
uint64_t arch_get_bitbase (HArchitecture arch);
uint64_t arch_get_wordbase (HArchitecture arch);

HRegister arch_get_register (HArchitecture arch, uint64_t index);
HRegister arch_get_register_by_id (HArchitecture arch, uint32_t index);
uint64_t arch_get_regcount (HArchitecture arch);

HStack arch_get_stack (HArchitecture arch, uint64_t index);
HStack arch_get_stack_by_id (HArchitecture arch, uint32_t index);
uint64_t arch_get_stackcount (HArchitecture arch);

HCallingConvention arch_get_cc (HArchitecture arch, uint64_t index);
HCallingConvention arch_get_cc_by_id (HArchitecture arch, uint32_t index);
uint64_t arch_get_cccount (HArchitecture arch);

HInstrDefinition arch_get_instrdef (HArchitecture arch, uint64_t index);
HInstrDefinition arch_get_instrdef_by_id (HArchitecture arch, uint32_t index);
uint64_t arch_get_instrdefcount (HArchitecture arch);



#ifdef __cplusplus
}
#endif

#endif //CHOLODEC_H
