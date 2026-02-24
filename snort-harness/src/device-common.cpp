#include "device.hpp"

#include <snort/snort.h>

SnortDevice snort_deviceCreateFromCommon(
	SnortCommonInterface const type,
	char const * const customLabel,
	char const * const romPath
) {
	// get the filepath from rompath. Get just the filename from the path,
	//   remove the extension, replace non-alphanumeric characters with dashes,
	//   and prepend "recordings/"
	std::string filepath = "";
	std::string romPathStr(romPath);
	size_t lastSlash = romPathStr.find_last_of("/\\");
	if (lastSlash != std::string::npos) {
		romPathStr = romPathStr.substr(lastSlash + 1);
	}
	size_t lastDot = romPathStr.find_last_of(".");
	if (lastDot != std::string::npos) {
		romPathStr = romPathStr.substr(0, lastDot);
	}
	for (char c : romPathStr) {
		if (std::isalnum(c)) {
			filepath += c;
			continue;
		}
		filepath += '-';
	}
	filepath += ".rpl";
	switch (type) {
		case kSnortCommonInterface_custom: {
			printf("cannot create device from common interface of type custom\n");
		}; break;
		case kSnortCommonInterface_chip8: {
			std::vector<SnortMemoryRegionCreateInfo> memoryRegions = {
				{
					.dataType = kSnortDt_u8,
					.elementCount = 4096u,
					.elementDisplayRowStride = 8u,
					.label = "memory",
				},
				{
					.dataType = kSnortDt_u16,
					.elementCount = 16u,
					.elementDisplayRowStride = 1u,
					.label = "stack",
				},
				{
					.dataType = kSnortDt_u8,
					.elementCount = 16u,
					.elementDisplayRowStride = 1u,
					.label = "registers",
				},
				{
					.dataType = kSnortDt_u16,
					.elementCount = 1u,
					.elementDisplayRowStride = 1u,
					.label = "register-index",
				},
				{
					.dataType = kSnortDt_u16,
					.elementCount = 1u,
					.elementDisplayRowStride = 1u,
					.label = "program-counter",
				},
				{
					.dataType = kSnortDt_u8,
					.elementCount = 1u,
					.elementDisplayRowStride = 1u,
					.label = "stack-pointer",
				},
				{
					.dataType = kSnortDt_r1,
					.elementCount = 64u * 32u,
					.elementDisplayRowStride = 64u,
					.label = "display",
				},
			};
			std::string recordingFilepath = (
				"replays/" + std::string(customLabel) + "-" + filepath
			);
			auto ci = SnortDeviceCreateInfo {
				.name = customLabel != nullptr ? customLabel : "chip8",
				.configPath = "configs/chip8.toml",
				.recordingFilepath = recordingFilepath.c_str(),
				.commonInterface = kSnortCommonInterface_chip8,
				.memoryRegionCount = 7u,
				.memoryRegions = &memoryRegions[0],
			};
			return snort_deviceCreate(&ci);
		}; break;
	}
	return SnortDevice { .handle = 0 };
}
