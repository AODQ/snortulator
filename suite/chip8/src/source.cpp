#include "device.hpp"

#include <snort-harness/snort-harness.h>
#include <snort-replay/fs.hpp>
#include <snort/snort.h>

#include "imgui.h"

#include <cstdio>
#include <vector>

int32_t main(int32_t const argc, char const * const argv[]) {

	if (argc < 2) {
		printf("usage: %s <rom path>\n", argv[0]);
		return 1;
	}

	SnortDevice snortDevice = (
		snort_deviceCreateFromCommon(
			kSnortCommonInterface_chip8,
			"snort-chip8",
			argv[1]
		)
	);
	ImGui::GetIO().IniFilename = "imgui-chip8.ini";

	Device device = device_initialize(argv[1], snortDevice);

	// the memory addresses don't change so can fetch and reuse
	auto const memoryRegions = std::vector<SnortMemoryRegion> {
		{ device.memory },
		{ (u8 *)device.stack },
		{ device.registers },
		{ (u8 *)&device.registerIndex },
		{ (u8 *)&device.programCounter },
		{ (u8 *)&device.stackPointer },
		{ device.display },
	};

	while (!snort_shouldQuit(snortDevice)) {
		u64 const framesToRun = (
			snort_startFrame(snortDevice, memoryRegions.data())
		);

		for (u64 it = 0; it < framesToRun; ++ it) {
			snort_updateFrame(snortDevice, memoryRegions.data());
			device_cpuStep(device);
		}

		snort_endFrame(snortDevice);
	}

	device_destroy(device);
	snort_deviceDestroy(&snortDevice);

	return 0;
}
