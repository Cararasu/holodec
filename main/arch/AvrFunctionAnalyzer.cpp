
#include "AvrFunctionAnalyzer.h"
#include "../Binary.h"

namespace holoavr{

	AVRFunctionAnalyzer::AVRFunctionAnalyzer(Architecture* arch): FunctionAnalyzer(arch) {

	}
	AVRFunctionAnalyzer::~AVRFunctionAnalyzer() {

	}

	bool AVRFunctionAnalyzer::canAnalyze(Binary* binary) {
		return holodec::caseCmpHString("avr", binary->arch->name);
	}

	bool AVRFunctionAnalyzer::init(Binary* binary) {
		this->binary = binary;



		return true;
	}
	bool AVRFunctionAnalyzer::terminate() {
		return true;
	}


	Register* getRegister(uint32_t index, Architecture* arch) {
		if (index >= 32)
			return nullptr;
		char buffer[5];
		snprintf(buffer, 5, "r%" PRId32, index);
		return arch->getRegister(buffer);
	}
	inline uint32_t parseRegType1Small(uint16_t value) {
		return value & 0x000F;
	}
	inline uint32_t parseRegType1Big(uint16_t value) {
		return (value & 0x000F) | ((value & 0x0200)>>5);
	}
	inline uint32_t parseRegType2Small(uint16_t value) {
		return (value >> 4) & 0x0F;
	}
	inline uint32_t parseRegType2Big(uint16_t value) {
		return (value >> 4) & 0x1F;
	}

	bool parseInstruction(Instruction* instr, Binary* binary, uint64_t addr, Architecture* arch) {

		instr->instrdef = nullptr;
		instr->size = 1;
		instr->addr = addr;

		uint16_t firstbytes = binary->getVData(addr);
		uint16_t secbytes = binary->getVData(addr + 1);

		if ((firstbytes & 0xFE00) == 0x9400) {//one reg instr
			switch (firstbytes & 0x000F) {
			case 0x00:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_COM);
				break;
			case 0x01:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_NEG);
				break;
			case 0x02:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SWAP);
				break;
			case 0x03:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_INC);
				break;
			case 0x05:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_ASR);
				break;
			case 0x06:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_LSR);
				break;
			case 0x07:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_ROR);
				break;
			case 0x08:
			case 0x09: {//wow that instruction set is weird
				//control transfer indirect
				if (firstbytes == 0x9409) {//ijmp
					instr->instrdef = arch->getInstrDef(AVR_INSTR_IJMP);
					return true;
				}
				else if (firstbytes == 0x9419) {//eijmp
					instr->instrdef = arch->getInstrDef(AVR_INSTR_EIJMP);
					return true;
				}
				else if (firstbytes == 0x9508) {//ret
					instr->instrdef = arch->getInstrDef(AVR_INSTR_RET);
					return true;
				}
				else if (firstbytes == 0x9509) {//icall
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ICALL);
					return true;
				}
				else if (firstbytes == 0x9518) {//reti
					instr->instrdef = arch->getInstrDef(AVR_INSTR_RETI);
					return true;
				}
				else if (firstbytes == 0x9519) {//eicall
					instr->instrdef = arch->getInstrDef(AVR_INSTR_EICALL);
					return true;
				}
				else if((firstbytes & 0xFF0F) == 0x9408) {
					uint16_t bit = (firstbytes & 0x70) >> 4;
					if (firstbytes & 0x080) {//clear sreg
						switch (bit) {
						case 0x00:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLC);
							return true;
						case 0x01:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLZ);
							return true;
						case 0x02:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLN);
							return true;
						case 0x03:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLV);
							return true;
						case 0x04:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLS);
							return true;
						case 0x05:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLH);
							return true;
						case 0x06:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLT);
							return true;
						case 0x07:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_CLI);
							return true;
						}
					}
					else {//set sreg
						switch (bit) {
						case 0x00:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEC);
							return true;
						case 0x01:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEZ);
							return true;
						case 0x02:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEN);
							return true;
						case 0x03:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEV);
							return true;
						case 0x04:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SES);
							return true;
						case 0x05:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEH);
							return true;
						case 0x06:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SET);
							return true;
						case 0x07:
							instr->instrdef = arch->getInstrDef(AVR_INSTR_SEI);
							return true;
						}
					}
				}
				return false;
			}
			break;
			case 0x0A:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_DEC);
				break;
			case 0x0B:{//des
				return false;//No idea what that is supposed to be
			}break;
			case 0x0C:
			case 0x0D:
			case 0x0E:
			case 0x0F: {//control transfer direct
				uint32_t dst = secbytes;
				dst |= (firstbytes & 0x01) << 16;
				dst |= (firstbytes & 0x1F0) << (17 - 4);
				instr->operands.push_back(IRArgument::createUVal(dst, arch->instrptrsize * arch->bitbase));
				instr->size = 2;
				if (firstbytes & 0x0002) {//call
					instr->instrdef = arch->getInstrDef(AVR_INSTR_CALL);
				}
				else {//jmp
					instr->jumpdest = dst;
					instr->instrdef = arch->getInstrDef(AVR_INSTR_JMP);
				}
				return true;
			}
			default:
				return false;
			}
			Register* reg = getRegister(parseRegType2Big(firstbytes), arch);
			if (!reg) {
				return false;
			}
			instr->operands.push_back(IRArgument::createReg(reg));
			return true;
		}
		if ((firstbytes & 0xC000) == 0x0000) {
			if ((firstbytes & 0x3C00) == 0x0000) {//16-bit move and floating point
				switch ((firstbytes & 0x0300) >> 8) {
				case 0x00:
					if (firstbytes == 0x0000) {
						instr->instrdef = arch->getInstrDef(AVR_INSTR_NOP);
						return true;
					}
					return false;
				case 0x01: {//movw
					uint32_t regId1 = parseRegType2Small(firstbytes) * 2;
					uint32_t regId2 = parseRegType1Small(firstbytes) * 2;

					instr->instrdef = arch->getInstrDef(AVR_INSTR_MOVW);
					Register* reg1a = nullptr;
					Register* reg1b = nullptr;
					Register* reg2a = nullptr;
					Register* reg2b = nullptr;

					if (regId1 == 26) {
						reg1a = arch->getRegister("x");
					}
					else if (regId1 == 28) {
						reg1a = arch->getRegister("y");
					}
					else if (regId1 == 30) {
						reg1a = arch->getRegister("z");
					}
					else {
						reg1a = getRegister(regId1, arch);
						reg1b = getRegister(regId1 + 1, arch);
					}
					if (regId2 == 26) {
						reg2a = arch->getRegister("x");
					}
					else if (regId2 == 28) {
						reg2a = arch->getRegister("y");
					}
					else if (regId2 == 30) {
						reg2a = arch->getRegister("z");
					}
					else {
						reg2a = getRegister(regId2, arch);
						reg2b = getRegister(regId2 + 1, arch);
					}
					if (!(reg1a && reg1a->id))
						return false;
					instr->operands.push_back(IRArgument::createReg(reg1a));
					if (reg1b && reg1b->id)
						instr->operands.push_back(IRArgument::createReg(reg1b));
					if (!(reg2a && reg2a->id))
						return false;
					instr->operands.push_back(IRArgument::createReg(reg2a));
					if (reg2b && reg2b->id)
						instr->operands.push_back(IRArgument::createReg(reg2b));
				}break;
				case 0x02: {//muls
					Register* reg1 = getRegister(parseRegType2Small(firstbytes) + 16, arch);
					Register* reg2 = getRegister(parseRegType2Small(firstbytes) + 16, arch);
					if (!(reg1 && reg1->id && reg2 && reg2->id)) {
						return false;
					}
					instr->instrdef = arch->getInstrDef(AVR_INSTR_MULS);
					instr->operands.push_back(IRArgument::createReg(reg1));
					instr->operands.push_back(IRArgument::createReg(reg2));
				}break;
				case 0x03: {//mulsu, fmul, fmuls, fmulsu
					Register* reg1 = getRegister((parseRegType2Small(firstbytes) % 8) + 16, arch);
					Register* reg2 = getRegister((parseRegType2Small(firstbytes) % 8) + 16, arch);
					if (!(reg1 && reg1->id && reg2 && reg2->id)) {
						return false;
					}
					switch (firstbytes & 0x0088) {
					case 0x00:
						instr->instrdef = arch->getInstrDef(AVR_INSTR_MULSU);
						break;
					case 0x08:
						instr->instrdef = arch->getInstrDef(AVR_INSTR_FMUL);
						break;
					case 0x80:
						instr->instrdef = arch->getInstrDef(AVR_INSTR_FMULS);
						break;
					case 0x88:
						instr->instrdef = arch->getInstrDef(AVR_INSTR_FMULSU);
						break;
					}
					instr->instrdef = arch->getInstrDef(AVR_INSTR_MULS);
					instr->operands.push_back(IRArgument::createReg(reg1));
					instr->operands.push_back(IRArgument::createReg(reg2));
				}break;
				}
				return true;
			}
			else if ((firstbytes & 0x3000) == 0x3000) {
				Register* reg1 = getRegister(parseRegType2Small(firstbytes) + 16, arch);
				uint16_t value = (firstbytes & 0xF) | ((firstbytes & 0x0F00) >> 4);
				if (!(reg1 && reg1->id)) {
					return false;
				}
				instr->instrdef = arch->getInstrDef(AVR_INSTR_CP);
				instr->operands.push_back(IRArgument::createReg(reg1));
				instr->operands.push_back(IRArgument::createUVal(value, 8));
				return true;
			}
			else {
				Register* reg1 = getRegister(parseRegType2Big(firstbytes), arch);
				Register* reg2 = getRegister(parseRegType1Big(firstbytes), arch);
				if (!(reg1 && reg1->id && reg2 && reg2->id)) {
					return false;
				}
				switch ((firstbytes & 0x3C00) >> 10) {
				case 0x1:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_CPC);
					break;
				case 0x2:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_SBC);
					break;
				case 0x3:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ADD);
					break;
				case 0x4:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_CPSE);
					break;
				case 0x5:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_CP);
					break;
				case 0x6:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_SUB);
					break;
				case 0x7:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ADC);
					break;
				case 0x8:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_AND);
					break;
				case 0x9:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_EOR);
					break;
				case 0xA:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_OR);
					break;
				case 0xB:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_MOV);
					break;
				default:
					return false;
				}
				instr->operands.push_back(IRArgument::createReg(reg1));
				instr->operands.push_back(IRArgument::createReg(reg2));
				return true;
			}

		}
		else if ((firstbytes & 0xFC00) == 0x9C00) {//mul
			Register* reg1 = getRegister(parseRegType2Big(firstbytes), arch);
			Register* reg2 = getRegister(parseRegType1Big(firstbytes), arch);
			if (!(reg1 && reg1->id && reg2 && reg2->id)) {
				return false;
			}
			instr->instrdef = arch->getInstrDef(AVR_INSTR_MUL);
			instr->operands.push_back(IRArgument::createReg(reg1));
			instr->operands.push_back(IRArgument::createReg(reg2));
			return true;
		}
		else if ((firstbytes & 0xF000) == 0xB000) {
			Register* reg1 = getRegister(parseRegType2Big(firstbytes), arch);
			if (!(reg1 && reg1->id)) {
				return false;
			}
			uint16_t value = (firstbytes & 0xF) | ((firstbytes & 0x600) >> 5);
			if (firstbytes & 0x0800) {//out
				instr->instrdef = arch->getInstrDef(AVR_INSTR_OUT);
				instr->operands.push_back(IRArgument::createUVal(value, arch->bytebase * arch->bitbase));
				instr->operands.push_back(IRArgument::createReg(reg1));
			}
			else {//in
				instr->instrdef = arch->getInstrDef(AVR_INSTR_IN);
				instr->operands.push_back(IRArgument::createReg(reg1));
				instr->operands.push_back(IRArgument::createUVal(value, arch->bytebase * arch->bitbase));
			}
			return true;
		}
		else if ((firstbytes & 0xFC00) == 0x9800) {//cbi, sbic, sbi, sbis
			uint16_t bit = firstbytes & 0x7;
			uint16_t ioreg = (firstbytes >> 3) & 0x1F;
			instr->operands.push_back(IRArgument::createUVal(ioreg, 16));
			instr->operands.push_back(IRArgument::createUVal(bit, 16));
			switch ((firstbytes >> 8) & 0x3) {
			case 0x00:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_CBI);
				return true;
			case 0x01: {
				Instruction nextinstr;
				if (!(parseInstruction(&nextinstr, binary, addr + instr->size, arch))) {
					return false;
				}
				instr->operands.push_back(IRArgument::createUVal(nextinstr.addr + nextinstr.size, arch->instrptrsize * arch->bitbase));
				instr->operands.push_back(IRArgument::createUVal(instr->addr + instr->size, arch->instrptrsize * arch->bitbase));
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBIC);
				return true;
			}
			case 0x02:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBI);
				return true;
			case 0x03:{
				Instruction nextinstr;
				if (!(parseInstruction(&nextinstr, binary, addr + instr->size, arch))) {
					return false;
				}
				instr->operands.push_back(IRArgument::createUVal(nextinstr.addr + nextinstr.size, arch->instrptrsize * arch->bitbase));
				instr->operands.push_back(IRArgument::createUVal(instr->addr + instr->size, arch->instrptrsize * arch->bitbase));
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBIS);
				return true;
			}
			}
			return false;
		}
		else if ((firstbytes & 0xFC0F) == 0x9000) {//sreg
			Register* reg = getRegister(parseRegType2Big(firstbytes), arch);
			if (!(reg && reg->id)) {
				return false;
			}
			if (firstbytes & 0x0200) {//lds
				instr->instrdef = arch->getInstrDef(AVR_INSTR_LD);
				instr->operands.push_back(IRArgument::createReg(reg));
				instr->operands.push_back(IRArgument::createUVal(secbytes, arch->instrptrsize * arch->bitbase));
				instr->size = 2;
			}
			else {//sts
				instr->instrdef = arch->getInstrDef(AVR_INSTR_ST);
				instr->operands.push_back(IRArgument::createUVal(secbytes, arch->instrptrsize * arch->bitbase));
				instr->operands.push_back(IRArgument::createReg(reg));
				instr->size = 2;
			}
			return true;
		}
		else if ((firstbytes & 0xF000) == 0xE000) {//ldi
			Register* reg = getRegister(parseRegType2Small(firstbytes) + 16, arch);
			if (!(reg && reg->id)) {
				return false;
			}
			instr->instrdef = arch->getInstrDef(AVR_INSTR_LDI);
			instr->operands.push_back(IRArgument::createReg(reg));
			instr->operands.push_back(IRArgument::createUVal((firstbytes & 0xF) | ((firstbytes& 0xF00) >> 4), 8));
			return true;
		}
		else if ((firstbytes & 0xC000) == 0x4000) {
			Register* reg = getRegister(parseRegType2Small(firstbytes) + 16, arch);
			if (!(reg && reg->id)) {
				return false;
			}
			instr->operands.push_back(IRArgument::createReg(reg));
			instr->operands.push_back(IRArgument::createUVal((firstbytes & 0xF) | ((firstbytes & 0xF00) >> 4), 8));
			switch (((firstbytes & 0x3000) >> 12) & 0x3) {
			case 0x00: //sbci
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBC);
				return true;
			case 0x01: //subi
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SUB);
				return true;
			case 0x02: //ori
				instr->instrdef = arch->getInstrDef(AVR_INSTR_OR);
				return true;
			case 0x03: //andi
				instr->instrdef = arch->getInstrDef(AVR_INSTR_AND);
				return true;
			}
			return false;
		}
		else if ((firstbytes & 0xFE00) == 0x9600) {
			uint16_t value = (firstbytes & 0xF) | ((firstbytes & 0x00C0) >> 2);

			switch ((firstbytes & 0x0030) >> 4) {
			case 0x0:
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("r24")));
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("r25")));
				break;
			case 0x1:
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				break;
			case 0x2:
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				break;
			case 0x3:
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				break;
			}
			instr->operands.push_back(IRArgument::createUVal((firstbytes & 0xF) | ((firstbytes & 0xC0) >> 2), 16));
			if (firstbytes & 0x0100) {//sbiw
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SUB);
			}
			else {//adiw
				instr->instrdef = arch->getInstrDef(AVR_INSTR_ADD);
			}
			return true;
		}
		else if ((firstbytes & 0xD000) == 0x8000) {
			Register* reg = getRegister(parseRegType2Big(firstbytes), arch);
			if (!(reg && reg->id))
				return false;
			uint16_t value = (firstbytes & 0x7) | ((firstbytes & 0xC00) >> 7) | ((firstbytes & 0x2000) >> 8);
			if ((firstbytes & 0x0208) == 0x0000) {//ldd Rd, Z+q
				instr->instrdef = arch->getInstrDef(AVR_INSTR_LDD);
				instr->operands.push_back(IRArgument::createReg(reg));
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				instr->operands.push_back(IRArgument::createUVal(value, 16));
			}
			else if ((firstbytes & 0x0208) == 0x0008) {//ldd Rd, Y+q
				instr->instrdef = arch->getInstrDef(AVR_INSTR_LDD);
				instr->operands.push_back(IRArgument::createReg(reg));
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				instr->operands.push_back(IRArgument::createUVal(value, 16));
			}
			else if ((firstbytes & 0x0208) == 0x0200) {//std Z+q, Rr
				instr->instrdef = arch->getInstrDef(AVR_INSTR_STD);
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				instr->operands.push_back(IRArgument::createUVal(value, 16));
				instr->operands.push_back(IRArgument::createReg(reg));
			}
			else if ((firstbytes & 0x0208) == 0x0208) {//std Y+q, Rr
				instr->instrdef = arch->getInstrDef(AVR_INSTR_STD);
				instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				instr->operands.push_back(IRArgument::createUVal(value, 16));
				instr->operands.push_back(IRArgument::createReg(reg));
			}
			return true;
		}
		else if ((firstbytes & 0xFC00) == 0x9000) {

			Register* reg = getRegister(parseRegType2Big(firstbytes), arch);
			if (!(reg && reg->id)) {
				return false;
			}
			if (firstbytes & 0x0200) {//store
				switch (firstbytes & 0x0F) {
				case 0x1: {//st Rd, Z+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				}break;
				case 0x2: {//st Rd, -Z
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				}break;
				case 0x9: {//st Rd, Y+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				}break;
				case 0xA: {//st Rd, -Y
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				}break;
				case 0xC: {//st Rd, X
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xD: {//st Rd, X+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xE: {//st Rd, X+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ST | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xF: {//push
					instr->instrdef = arch->getInstrDef(AVR_INSTR_PUSH);
				}break;
				default:
					return false;
				}
				instr->operands.push_back(IRArgument::createReg(reg));
			}
			else {//store
				instr->operands.push_back(IRArgument::createReg(reg));
				switch (firstbytes & 0x0F) {
				case 0x1: {//ld Rd, Z+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				}break;
				case 0x2: {//ld Rd, -Z
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
				}break;
				case 0x4: {//lpm Rd, Z
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LPM);
				}break;
				case 0x5: {//lpm Rd, Z+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LPM | AVR_INSTR_INC_PTR);
				}break;
				case 0x6: {//elpm rd, Z+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ELPM);
				}break;
				case 0x7: {//elpm rd, Z
					instr->instrdef = arch->getInstrDef(AVR_INSTR_ELPM | AVR_INSTR_INC_PTR);
				}break;
				case 0x9: {//ld Rd, Y+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				}break;
				case 0xA: {//ld Rd, -Y
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("y")));
				}break;
				case 0xC: {//ld Rd, X
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xD: {//ld Rd, X+
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_INC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xE: {//ld Rd, -X
					instr->instrdef = arch->getInstrDef(AVR_INSTR_LD | AVR_INSTR_DEC_PTR);
					instr->operands.push_back(IRArgument::createReg(arch->getRegister("x")));
				}break;
				case 0xF: {//pop
					instr->instrdef = arch->getInstrDef(AVR_INSTR_POP);
				}break;
				default:
					return false;
				}
			}
			return true;
		}
		else if (firstbytes == 0x95C8) {//lpm R0, Z
			instr->operands.push_back(IRArgument::createReg(arch->getRegister("r0")));
			instr->instrdef = arch->getInstrDef(AVR_INSTR_LPM | AVR_INSTR_INC_PTR);
			instr->operands.push_back(IRArgument::createReg(arch->getRegister("z")));
			return true;
		}
		else if ((firstbytes & 0xF808) == 0xF800) {//one reg instr
			uint32_t regId = (firstbytes >> 0x4) & 0x1F;
			Register* reg = getRegister(parseRegType2Big(firstbytes), arch);
			if (!(reg && reg->id)) {
				return false;
			}
			uint32_t bitIndex = firstbytes & 0x07;
			instr->operands.push_back(IRArgument::createReg(reg));
			instr->operands.push_back(IRArgument::createUVal(bitIndex, arch->bytebase * arch->bitbase));
			switch ((firstbytes & 0x0600) >> 9) {
			case 0x00:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_BLD);
				break;
			case 0x01:
				instr->instrdef = arch->getInstrDef(AVR_INSTR_BST);
				break;
			case 0x02: {
				Instruction nextinstr;
				if (!(parseInstruction(&nextinstr, binary, addr + instr->size, arch))) {
					return false;
				}
				instr->operands.push_back(IRArgument::createUVal(nextinstr.addr + nextinstr.size, arch->instrptrsize * arch->bitbase));
				instr->operands.push_back(IRArgument::createUVal(instr->addr + instr->size, arch->instrptrsize * arch->bitbase));
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBRC);
				return true;
			}
			case 0x03:{
				Instruction nextinstr;
				if (!(parseInstruction(&nextinstr, binary, addr + instr->size, arch))) {
					return false;
				}
				instr->operands.push_back(IRArgument::createUVal(nextinstr.addr + nextinstr.size, arch->instrptrsize * arch->bitbase));
				instr->operands.push_back(IRArgument::createUVal(instr->addr + instr->size, arch->instrptrsize * arch->bitbase));
				instr->instrdef = arch->getInstrDef(AVR_INSTR_SBRS);
				return true;
			}
			}
			return true;
		}
		else if ((firstbytes & 0xE000) == 0xC000) {//control transfer relative
			int16_t rel = firstbytes & 0x0FFF;
			if (rel & 0x800) {
				instr->jumpdest = instr->addr + instr->size - 0x1000 + rel;
			}
			else {
				instr->jumpdest = instr->addr + instr->size + rel;
			}
			instr->operands.push_back(IRArgument::createUVal(instr->jumpdest, arch->instrptrsize * arch->bitbase));
			if (firstbytes & 0x1000) {//rcall
				instr->instrdef = arch->getInstrDef(AVR_INSTR_CALL);
			}
			else {//rjmp
				instr->instrdef = arch->getInstrDef(AVR_INSTR_JMP);
			}
			return true;
		}
		else if ((firstbytes & 0xF800) == 0xF000) {
			uint16_t value = (firstbytes & 0x03f8) >> 3;
			if (value & 0x40) {
				instr->jumpdest = instr->addr + instr->size + value - 0x80;
			}
			else {
				instr->jumpdest = instr->addr + instr->size + value;
			}
			instr->nojumpdest = instr->addr + instr->size;
			instr->operands.push_back(IRArgument::createUVal(instr->jumpdest, arch->instrptrsize * arch->bitbase));
			instr->operands.push_back(IRArgument::createUVal(instr->nojumpdest, arch->instrptrsize * arch->bitbase));
			if (firstbytes & 0x0400) {//br on clear
				switch (firstbytes & 0x7) {
				case 0x0:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRCC);
					break;
				case 0x1:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRNE);
					break;
				case 0x2:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRPL);
					break;
				case 0x3:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRVC);
					break;
				case 0x4:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRGE);
					break;
				case 0x5:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRHC);
					break;
				case 0x6:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRID);
					break;
				}
				return true;
			}
			else {//br on set
				switch (firstbytes & 0x7) {
				case 0x0:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRCS);
					break;
				case 0x1:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BREQ);
					break;
				case 0x2:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRMI);
					break;
				case 0x3:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRVS);
					break;
				case 0x4:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRLT);
					break;
				case 0x5:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRHS);
					break;
				case 0x6:
					instr->instrdef = arch->getInstrDef(AVR_INSTR_BRIE);
					break;
				}
				return true;
			}
		}
		else if (firstbytes == 0x9588) {//sleep
			instr->instrdef = arch->getInstrDef(AVR_INSTR_SLEEP);
			return true;
		}
		else if (firstbytes == 0x9598) {//break
			instr->instrdef = arch->getInstrDef(AVR_INSTR_BREAK);
			return true;
		}
		else if (firstbytes == 0x95A8) {//wdr
			instr->instrdef = arch->getInstrDef(AVR_INSTR_WDR);
			return true;
		}
		printf("Cannot disassemble Instruction 0x%x,\n", firstbytes);
		return false;
	}

	bool AVRFunctionAnalyzer::analyzeInsts(size_t addr) {
		printf("Disassembling at position 0x%x\n", addr);


		do {
			Instruction instruction;

			if (!parseInstruction(&instruction, binary, addr, arch)) {
				printf("Cannot disassemble at Addr 0x%x,\n", addr);
				return false;
			}

			//instruction.print(arch);
			addr += instruction.size;
			if (!postInstruction(&instruction))
				break;
		} while (true);
		return true;
	}

}