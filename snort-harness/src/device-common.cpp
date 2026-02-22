#include "device.hpp"

#include <snort/snort.h>

SnortDevice snort_deviceCreateFromCommon(SnortCommonInterface const type) {
	switch (type) {
		case kSnortCommonInterface_custom: {
			printf("cannot create device from common interface of type custom\n");
		}; break;
		case kSnortCommonInterface_chip8: {
			auto ci = SnortDeviceCreateInfo {
				.name = "chip8",
				.commonInterface = kSnortCommonInterface_chip8,
				.memoryRegionCount = 7u,
				.memoryRegions = (SnortMemoryRegionCreateInfo const []) {
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
				},
			};
			return snort_deviceCreate(&ci);
		}; break;
	}
	return SnortDevice { .handle = 0 };
}
