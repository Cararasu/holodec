
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

# Current IR Specs
The Intermediate Representation is written in prefix notation.
```
#add(#arg1,#arg2)
```
A sequence of operations is defined with `&`:
```
#shl(#arg1,1)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($a,#a)
```
For multiple operations in a sequence the value of the expression is the value of the first operation:
```
=(#arg1,+(#arg1,#arg2)&=($z,#z)&=($p,#p)&=($s,#s)&=($o,#o)&=($c,#c)&=($a,#a))
```
Only a range of bits in a value/register can be accessed via `['pos':'size']` or in case only one bit is needed `['pos']` where `pos` is the position starting with `0` and `size` is the number of bits taken. 
```
=(#arg1,#t0[0:#size(#arg1)])&=($c,#t0[#size(#arg1)]))
```
In case a register is accessed it can still be written to via assignment.
```
=(#arg1[0:32],#fsub(#arg1[0:32],#arg2[0:32]))&
=(#arg1[32:32],#fadd(#arg1[32:32],#arg2[32:32]))&
=(#arg1[64:32],#fsub(#arg1[64:32],#arg2[64:32]))&
=(#arg1[96:32],#fadd(#arg1[96:32],#arg2[96:32]))
```

## `#`-Prefix
### Internal Flags
these Flags are implicitly set After every arithmetic operation
* `#c`
    * Carry Flag
* `#a`
    * Half-Carry Flag
* `#p`
    * Parity Flag
* `#o`
    * Overflow Flag
* `#z`
    * Zero Flag
* `#s`
    * Signed Flag

### Variables
* `#arg['n'] (0-ary)`
    * The `n`th argument of the instruction.
* `#stck['n'] (0-ary)`
    * The `n`th element on the stack.
* `#t['n'] (0-ary)`
    * The `n`th temporary value.

### Functions

* `#ret (0-ary)`
    * Defines a return from a function. This does not assume that the return address is on the stack. It is completely independant of an architecture, but it terminates a function.
* `#jmp (1-ary)`
    * A jump
* `#call (1-ary)`
    * Calls a function
* `#trap (0-ary)`
    * Trap
* `#syscall (1-ary)`
    * Calls a function
* `=, #assign (2-ary)`
    * Assignment
* `#size (1-ary)`
    * Returns the bits of the argument
* `#popcnt (1-ary)`
    * Number of bits set
* `?, #if (2-ary)`
    * 1st Argument is the condition, 2nd Argument is the Body
* `#loop (2-ary)`
    * 1st Argument is the condition, 2nd Argument is the Body
* `#rec['mnemonic'] (n-ary)`
    * Calls the Instruction identified by `'mnemonic'`
* `#extend (2-ary)`
    * zero extend of 1st argument to the size of 2nd argument
* `#sextend (2-ary)`
    * Signed extend of 1st argument to the size of 2nd argument

#### Arithmetic
* `+, #add (2+-ary)`
    * Addition
* `#fadd (2+-ary)`
    * Floating-point Addition
* `-, #sub (2+-ary)`
    * Subtraction
* `#fsub (2+-ary)`
    * Floating-point Subtraction
* `*, #mul (2+-ary)`
    * Multiplication
* `#smul (2+-ary)`
    * Signed Multiplication
* `#fmul (2+-ary)`
    * Floating-point Multiplication
* `#div (2-ary)`
    * Division
* `#sdiv (2-ary)`
    * Signed Division
* `#fdiv (2-ary)`
    * Floating-point Division

#### Memory Operands
* `#st (2-ary)`
    * Stores 2nd Argument in Memory location that is pointed to by the first Argument
* `#ld (2-ary)`
    * Loads (2nd Argument) number of bytes from the (first Argument) memory location

#### Comparisons
* `<>, #neq (2-ary)`
    * Not Equals
* `==, #eq (2-ary)`
    * Equals
* `<, #l (2-ary)`
    * Smaller
* `<=, #le (2-ary)`
    * Smaller Equals
* `>, #g (2-ary)`
    * Greater
* `>=, #ge (2-ary)`
    * Greater Equals
* `#not (1-ary)`
    * Is 0

#### Bit Operators
* `#band (2+-ary)`
    * Binary and
* `#bor (2+-ary)`
    * Binary or
* `#bxor (2+-ary)`
    * Binary xor
* `#bnot (1-ary)`
    * Binary flip of bits
* `#shr (2-ary)`
    * Shift right
* `#shl (2-ary)`
    * Shift left
* `#sar (2-ary)`
    * Shift arithmetic right
* `#sal (2-ary)`
    * Shift arithmetic left
* `#ror (2-ary)`
    * Rotate right
* `#rot (2-ary)`
    * Rotate right

#### Cast
* `#i2f`
    * Integer to Floating point
* `#f2i`
    * Floating point to Integer

# `$`-Prefix
Everthing with the `$`-prefix is user defined. Registers are `0-ary`. Undefined Instructions are automatically created as `$mnemonic`
```
Examples: $rax, $rbx, $rsp
```









