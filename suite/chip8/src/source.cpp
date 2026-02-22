#include "device.hpp"

#include <snort-harness/snort-harness.h>
#include <snort-replay/fs.hpp>
#include <snort/snort.h>

#include "imgui.h"

#include <cstdio>

int32_t main(int32_t const argc, char const * const argv[]) {
	SnortDevice snortDevice = (
		snort_deviceCreateFromCommon(kSnortCommonInterface_chip8)
	);
	ImGui::GetIO().IniFilename = "imgui-chip8.ini";

	if (argc < 2) {
		printf("usage: %s <rom path>\n", argv[0]);
		return 1;
	}

	Device device = device_initialize(argv[1], snortDevice);

	while (!snort_shouldQuit(snortDevice)) {
		bool const shouldRunFrame = (
			snort_startFrame(
				snortDevice,
				(SnortMemoryRegion const []) {
					{ device.memory },
					{ (u8 *)device.stack },
					{ device.registers },
					{ (u8 *)&device.registerIndex },
					{ (u8 *)&device.programCounter },
					{ (u8 *)&device.stackPointer },
					{ device.display },
				}
			)
		);

		if (shouldRunFrame) {
			device_cpuStep(device);
		}

		snort_endFrame(snortDevice);
	}

	device_destroy(device);
	snort_deviceDestroy(&snortDevice);

	return 0;
}
