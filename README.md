
# HoloDec
The goal of HoloDec is to write an open source decompiler for x86/x86-64 binaries. For starters only ELF binaries with x86-64 will be supported, but the process is going to be extendable to support multiple architectures.
## Currently Planned Features
* Support of x86, x86-64, ARM and MIPS instruction sets (ARM and MIPS at a later point)
* Support of ELF and PE binaries
* Scripting support for dynamically interacting with the program, so that results of all steps can be changed or overwritten
* Recursive descending disassembler(in the works)
* Semantic based Decompiler
    * Raising of disassembled result into intermediate representation(IR)
    * Probably convert IR into an SSA form
    * Generation of Pseudocode from SSA
* Maybe a structural decompiler (something easy like Python just to show possibilites)
    * A per-instructionset decompiler








