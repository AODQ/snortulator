#pragma once

#include <snort/snort.h>
#include <snort-harness/snort-harness.h>

#include <string>

struct Device {
	u8 memory[4096u];
	u16 stack[16u];
	u8 registers[16u];
	u16 registerIndex { 0u };
	u16 programCounter { 0x200u };
	u8 stackPointer { 0u };

	u8 display[64u * 32u];

	SnortDevice snortDevice = { 0 };
};

Device device_initialize(
	char const * const romPath,
	SnortDevice const & snortDevice
);
void device_destroy(Device & device);

void device_cpuStep(Device & device);
