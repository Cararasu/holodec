
# Current IR Specs
The Intermediate Representation is written in prefix notation.
```
#add(#arg[1],#arg[2])
```
Only a range of bits in a value/register can be accessed via `['pos',size']` or in case only one bit is needed `['pos']` where `pos` is the position starting with `0` and `size` is the number of bits taken. 0 means the rest of the variable
```
=(#arg1,#t[1][0,#size(#arg[1])])&=($c,#t0[#size(#arg[1])]))
```
Write to a register may only happen for a whole register
```
Not like this:
=(#arg[1],#fsub(#arg[1][0,32],#arg[2][0,32]))
Like this:
=(#arg[1],#app(#fadd(#arg[1][0,32],#arg[2][0,32]),#arg[1][32,0]))
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
    * The `n`th argument of the instruction. 0 means invalid
* `#stck['n'] (0-ary)`
    * The `n`th element on the stack. 0 means invalid
* `#t['n'] (0-ary)`
    * The `n`th temporary value. 0 means invalid

### Functions
* `#seq (n-ary)`
   * A sequence of operations
```
#seq(=(#arg[1],#shl(#arg[1],1)),($z,#z),=($p,#p),=($s,#s),=($o,#o),=($a,#a))
```
* `#app (n-ary)`
   * A sequence of operations
```
#seq(=(#arg[1],#shl(#arg[1],1)),($z,#z),=($p,#p),=($s,#s),=($o,#o),=($a,#a))
```

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
* `#sadd (2+-ary)`
    * Signed Addition
* `#fadd (2+-ary)`
    * Floating-point Addition
* `-, #sub (2+-ary)`
    * Subtraction
* `#ssub (2+-ary)`
    * Signed Subtraction
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
Everthing with the `$`-prefix is user defined. Registers and Stacks are `0-ary`. Stacks may only be used with `#pop` and `#push`.
```
Examples: $rax, $rbx, $rsp
#push($mem,#t[1])
```

