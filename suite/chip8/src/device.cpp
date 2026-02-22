#include "device.hpp"

#include <array>
#include <cstdio>
#include <cstring>

// -----------------------------------------------------------------------------

namespace instr {
	u16 iClear(Device & device) {
		memset(device.display, 0, sizeof(device.display));
		return 2u;
	}
	u16 iReturn(Device & device) {
		device.programCounter = device.stack[--device.stackPointer];
		return 2u;
	}
	u16 iJump(Device & device, u16 const address) {
		device.programCounter = address;
		return 0u;
	}
	u16 iCall(Device & device, u16 const address) {
		device.stack[device.stackPointer++] = device.programCounter + 2u;
		device.programCounter = address;
		return 0u;
	}
	u16 iIfRegNeqNN(Device & device, u8 const reg, u8 const value) {
		if (device.registers[reg] == value) {
			return 4u;
		}
		return 2u;
	}
	u16 iIfRegEqNN(Device & device, u8 const reg, u8 const value) {
		if (device.registers[reg] != value) {
			return 4u;
		}
		return 2u;
	}
	u16 iIfRegNeqReg(Device & device, u8 const regX, u8 const regY) {
		if (device.registers[regX] == device.registers[regY]) {
			return 4u;
		}
		return 2u;
	}
	u16 iRegLoadNN(Device & device, u8 const reg, u8 const value) {
		device.registers[reg] = value;
		return 2u;
	}
	u16 iRegAddNN(Device & device, u8 const reg, u8 const value) {
		device.registers[reg] += value;
		return 2u;
	}
	u16 iRegLoadReg(Device & device, u8 const regX, u8 const regY) {
		device.registers[regX] = device.registers[regY];
		return 2u;
	}
	u16 iRegOrReg(Device & device, u8 const regX, u8 const regY) {
		device.registers[regX] |= device.registers[regY];
		return 2u;
	}
	u16 iRegAndReg(Device & device, u8 const regX, u8 const regY) {
		device.registers[regX] &= device.registers[regY];
		return 2u;
	}
	u16 iRegXorReg(Device & device, u8 const regX, u8 const regY) {
		device.registers[regX] ^= device.registers[regY];
		return 2u;
	}
	u16 iRegAddRegWithCarry(Device & device, u8 const regX, u8 const regY) {
		u16 const reg0 = (u16)(device.registers[regX]);
		u16 const reg1 = (u16)(device.registers[regY]);
		u16 const sum = reg0 + reg1;
		device.registers[0xFu] = (sum > 0xFFu) ? 1u : 0u;
		device.registers[regX] = (u8)(sum & 0xFFu);
		return 2u;
	}
	u16 iRegSubRegWithBorrow(Device & device, u8 const regX, u8 const regY) {
		u8 const reg0 = device.registers[regX];
		u8 const reg1 = device.registers[regY];
		device.registers[0xFu] = (reg0 > reg1) ? 1u : 0u;
		device.registers[regX] = reg0 - reg1;
		return 2u;
	}
	u16 iRegShiftLeft(Device & device, u8 const reg) {
		device.registers[0xFu] = (device.registers[reg] & 0x80u) >> 7u;
		device.registers[reg] <<= 1u;
		return 2u;
	}
	u16 iRegShiftRight(Device & device, u8 const reg) {
		device.registers[0xFu] = device.registers[reg] & 0x1u;
		device.registers[reg] >>= 1u;
		return 2u;
	}
	u16 ifRegEqReg(Device & device, u8 const regX, u8 const regY) {
		if (device.registers[regX] != device.registers[regY]) {
			return 4u;
		}
		return 2u;
	}
	u16 iIndexLoad(Device & device, u16 const address) {
		device.registerIndex = address;
		return 2u;
	}
	u16 iJumpWithRegOffset(Device & device, u16 const address) {
		device.programCounter = address + device.registers[0x0u];
		return 0u;
	}
	u16 iRegLoadRandomAndNN(Device & device, u8 const reg, u8 const value) {
		u64 const rand = snort_rngU64(device.snortDevice);
		u8 const randByte = (u8)(rand & 0xFFu);
		device.registers[reg] = randByte & value;
		return 2u;
	}
	u16 iDrawSprite(
		Device & device, u8 const regX, u8 const regY, u8 const height
	) {
		// TODO
		return 2u;
	}
	u16 iSkipIfKeyPressed(Device & device, u8 const reg) {
		// TODO
		return 2u;
	}
	u16 iSkipIfKeyNotPressed(Device & device, u8 const reg) {
		// TODO
		return 2u;
	}
	u16 iSoundDelayTimerLoad(Device & device, u8 const reg) {
		// TODO
		return 2u;
	}
	u16 iSoundDelayTimerStore(Device & device, u8 const reg) {
		// TODO
		return 2u;
	}
	u16 iIndexAddReg(Device & device, u8 const reg) {
		device.registerIndex += device.registers[reg];
		return 2u;
	}
	u16 iIndexLoadSpriteAddr(Device & device, u8 const reg) {
		// TODO
		return 2u;
	}
	u16 iIndexLoadBcdOfReg(Device & device, u8 const reg) {
		u8 const value = device.registers[reg];
		device.memory[device.registerIndex + 0u] = value / 100u;
		device.memory[device.registerIndex + 1u] = (value / 10u) % 10u;
		device.memory[device.registerIndex + 2u] = value % 10u;
		return 2u;
	}
	u16 iIndexLoadRegs(Device & device, u8 const reg) {
		for (u16 it = 0u; it <= reg; ++it) {
			device.memory[device.registerIndex + it] = device.registers[it];
		}
		return 2u;
	}
	u16 iIndexStoreRegs(Device & device, u8 const reg) {
		for (u16 it = 0u; it <= reg; ++it) {
			device.registers[it] = device.memory[device.registerIndex + it];
		}
		return 2u;
	}
}

// -----------------------------------------------------------------------------

static constexpr std::array<uint8_t, 200u> initialRomData = {
	0xf0, 0x90, 0x90, 0x90, 0xf0, 0x20, 0x60, 0x20,
	0x20, 0x70, 0xf0, 0x10, 0xf0, 0x80, 0xf0, 0xf0,
	0x10, 0xf0, 0x10, 0xf0, 0x90, 0x90, 0xf0, 0x10,
	0x10, 0xf0, 0x80, 0xf0, 0x10, 0xf0, 0xf0, 0x80,
	0xf0, 0x90, 0xf0, 0xf0, 0x10, 0x20, 0x40, 0x40,
	0xf0, 0x90, 0xf0, 0x90, 0xf0, 0xf0, 0x90, 0xf0,
	0x10, 0xf0, 0xf0, 0x90, 0xf0, 0x90, 0x90, 0xe0,
	0x90, 0xe0, 0x90, 0xe0, 0xf0, 0x80, 0x80, 0x80,
	0xf0, 0xe0, 0x90, 0x90, 0x90, 0xe0, 0xf0, 0x80,
	0xf0, 0x80, 0xf0, 0xf0, 0x80, 0xf0, 0x80, 0x80,
};

// -----------------------------------------------------------------------------

Device device_initialize(
	[[maybe_unused]] char const * const romPath,
	SnortDevice const & snortDevice
) {
	Device device {};
	memset(device.memory, 0, sizeof(device.memory));
	device.snortDevice = snortDevice;
	device.programCounter = 0x200u;

	// set the initial font data
	memcpy(
		/*__dest=*/ &device.memory[0u],
		/*__src=*/ initialRomData.data(),
		/*__n=*/ initialRomData.size()
	);

	// load ROM if provided
	if (romPath != nullptr && romPath[0] != '\0') {
		printf("Loading ROM: %s\n", romPath);
		FILE * const romFile = fopen(romPath, "rb");
		if (romFile == nullptr) {
			printf("Failed to open ROM file: %s\n", romPath);
		} else {
			size_t numBytes = 0;
			fseek(romFile, 0, SEEK_END);
			numBytes = ftell(romFile);
			fseek(romFile, 0, SEEK_SET);
			if (numBytes > (sizeof(device.memory) - 0x200u)) {
				numBytes = sizeof(device.memory) - 0x200u;
				printf(
					"ROM truncated to %zu bytes to fit in memory\n",
					numBytes
				);
			}
			fread(
				/*__ptr=*/ &device.memory[0] + 0x200u, // font at 0x000
				/*__size=*/ 1,
				/*__n=*/ numBytes,
				/*__stream=*/ romFile
			);
			fclose(romFile);
		}
	}

	return device;
}

// -----------------------------------------------------------------------------

void device_destroy(Device & device) {
	// TODO
}

// -----------------------------------------------------------------------------


static u8 device_processInstr(Device & device){
	// -- fetch opcode
	u16 const opcode = (
		  (u16)(device.memory[device.programCounter]) << 8u
		| (u16)(device.memory[device.programCounter + 1u])
	);

	// -- decode and execute
	u8 const msb0 = (opcode & 0xF000u) >> 12u;
	u8 const msb1 = (opcode & 0x0F00u) >> 8u;
	u8 const msb2 = (opcode & 0x00F0u) >> 4u;
	u8 const msb3 = (opcode & 0x000Fu);
	switch (msb0) {
		case 0x0:
			switch (opcode) {
				case 0x00E0:
					return instr::iClear(device);
				case 0x00EE:
					return instr::iReturn(device);
				default:
					break;
			}
			break;
		break;
		case 0x1:
			return instr::iJump(device, opcode & 0x0FFFu);
		case 0x2:
			return instr::iCall(device, opcode & 0x0FFFu);
		case 0x3:
			return instr::iIfRegEqNN(device, msb1, (u8)(opcode & 0x00FFu));
		case 0x4:
			return instr::iIfRegNeqNN(device, msb1, (u8)(opcode & 0x00FFu));
		case 0x5:
			if (msb3 == 0x0u) {
				return instr::iIfRegNeqReg(device, msb1, msb2);
			}
			break;
		case 0x6:
			return instr::iRegLoadNN(device, msb1, (u8)(opcode & 0x00FFu));
		case 0x7:
			return instr::iRegAddNN(device, msb1, (u8)(opcode & 0x00FFu));
		case 0x8:
			switch (msb3) {
				case 0x0: return instr::iRegLoadReg(device, msb1, msb2);
				case 0x1: return instr::iRegOrReg(device, msb1, msb2);
				case 0x2: return instr::iRegAndReg(device, msb1, msb2);
				case 0x3: return instr::iRegXorReg(device, msb1, msb2);
				case 0x4: return instr::iRegAddRegWithCarry(device, msb1, msb2);
				case 0x5: return instr::iRegSubRegWithBorrow(device, msb1, msb2);
				case 0x6: return instr::iRegShiftRight(device, msb1);
				case 0x7: return instr::iRegSubRegWithBorrow(device, msb2, msb1);
				case 0xE: return instr::iRegShiftLeft(device, msb1);
				default: break;
			}
			break;
		case 0x9:
			if (msb3 == 0x0u) {
				return instr::iIfRegNeqReg(device, msb1, msb2);
			}
			break;
		case 0xA:
			return instr::iJump(device, opcode & 0x0FFFu);
		case 0xB:
			return instr::iJumpWithRegOffset(device, opcode & 0x0FFFu);
		case 0xC:
			return instr::iRegLoadRandomAndNN(
				device, msb1, (u8)(opcode & 0x00FFu)
			);
		case 0xD:
			return instr::iDrawSprite(device, msb1, msb2, msb3);
		case 0xE:
			if (msb2 == 0x9u && msb3 == 0xEu) { // 9E
				return instr::iSkipIfKeyPressed(device, msb1);
			}
			if (msb2 == 0xAu && msb3 == 0x1u) { // A1
				return instr::iSkipIfKeyNotPressed(device, msb1);
			}
			break;
		case 0xF:
			if (msb2 == 0x0u && msb3 == 0x7u) { // 07
				return instr::iSoundDelayTimerLoad(device, msb1);
			}
			if (msb2 == 0x1u && msb3 == 0x5u) { // 15
				return instr::iSoundDelayTimerStore(device, msb1);
			}
			if (msb2 == 0x1u && msb3 == 0xEu) { // 1E
				return instr::iIndexAddReg(device, msb1);
			}
			if (msb2 == 0x2u && msb3 == 0x9u) { // 29
				return instr::iIndexLoadSpriteAddr(device, msb1);
			}
			if (msb2 == 0x3u && msb3 == 0x3u) { // 33
				return instr::iIndexLoadBcdOfReg(device, msb1);
			}
			if (msb2 == 0x5u && msb3 == 0x5u) { // 55
				return instr::iIndexLoadRegs(device, msb1);
			}
			if (msb2 == 0x6u && msb3 == 0x5u) { // 65
				return instr::iIndexStoreRegs(device, msb1);
			}
		break;
	}
	return 2u; // default to 2 bytes per instruction
}

// -----------------------------------------------------------------------------

void device_cpuStep(Device & device) {
	device.programCounter += device_processInstr(device);
}
