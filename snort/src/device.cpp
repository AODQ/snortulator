#include "device.hpp"

#include "imgui-display.hpp"

#include <cstring>

namespace {

std::vector<snort::MemoryRegionDelta> storeFrameDelta(
	snort::Device & device,
	SnortMemoryRegion const * memoryRegions,
	size_t const regionIndex
) {
	std::vector<snort::MemoryRegionDelta> delta;
	auto & regionInfo = device.currentMemoryRegion[regionIndex];
	auto & referenceData = memoryRegions[regionIndex].data;
	size_t startByteDiff = -1u;
	// look through bytes of memory region, find spans of ranges that are
	//   different, and store them as deltas. The deltas are based off
	//   the old data, so that the data can be rewinded
	for (size_t byteIt = 0; byteIt < regionInfo.byteCount; ++ byteIt) {
		bool const isDiff = (
			referenceData[byteIt] != regionInfo.currentData[byteIt]
		);
		bool const hasStartedDiff = (startByteDiff != -1u);
		// if byte isn't different and no previous diff seen, continue search
		if (!isDiff && !hasStartedDiff) {
			continue;
		}
		// if byte isn't different, and previous diff seen, store the diff
		else if (!isDiff && hasStartedDiff) {
			delta.emplace_back(
				snort::MemoryRegionDelta {
					.byteOffset = startByteDiff,
					.deltaData = std::vector<uint8_t>(
						&referenceData[startByteDiff],
						&referenceData[byteIt]
					),
				}
			);
			startByteDiff = -1u;
		}
		// if byte is different, and no previous diff seen, start diff
		else if (isDiff && !hasStartedDiff) {
			startByteDiff = byteIt;
		}
		// if byte is different, and previous diff seen, continue diff search
		else if (isDiff && hasStartedDiff) {
			continue;
		}
		else {
			SnortAssert(false && "unreachable");
		}
	}
	return delta;
}

} // namespace

// --

size_t snort::dtByteCount(SnortDt const dt) {
	switch (dt) {
		case kSnortDt_u8: return 1u;
		case kSnortDt_u16: return 2u;
		case kSnortDt_u32: return 4u;
		case kSnortDt_u64: return 8u;
		case kSnortDt_i8: return 1u;
		case kSnortDt_i16: return 2u;
		case kSnortDt_i32: return 4u;
		case kSnortDt_i64: return 8u;
		case kSnortDt_f32: return 4u;
		case kSnortDt_r8: return 1u;
		case kSnortDt_rgba8: return 4u;
		default: return 1u;
	}
}

// --

SnortDevice snort_deviceCreate(
	SnortDeviceCreateInfo const * const ci
) {
	snort::Device device = {
		.name = std::string(ci->name),
		.frameHistory = {},
		.currentMemoryRegion = {},
	};

	// -- initialize raylib + imgui
	SetTraceLogLevel(LOG_ERROR);
	InitWindow(1200, 600, ci->name);
	SetTargetFPS(60);
	snort::displayInitialize(device);

	// -- register memory regions
	for (size_t it = 0; it < ci->memoryRegionCount; ++ it) {
		auto const & regionCi = ci->memoryRegions[it];
		size_t const width = regionCi.elementDisplayRowStride;
		size_t const height = (
			regionCi.elementCount / regionCi.elementDisplayRowStride
		);
		Image image {};
		Texture2D texture {};
		if (regionCi.dataType == kSnortDt_r8) {
			image = GenImageColor(width, height, BLACK);
			texture = LoadTextureFromImage(image);
		}
		else if (regionCi.dataType == kSnortDt_rgba8) {
			image = GenImageColor(width, height, BLANK);
			texture = LoadTextureFromImage(image);
		}
		snort::MemoryRegionInfo const regionInfo = {
			.dataType = regionCi.dataType,
			.byteCount = (
				snort::dtByteCount(regionCi.dataType) * regionCi.elementCount
			),
			.byteStride = snort::dtByteCount(regionCi.dataType),
			.elementCount = regionCi.elementCount,
			.elementDisplayRowStride = regionCi.elementDisplayRowStride,
			.label = std::string(regionCi.label),
			.currentData = std::vector<uint8_t>(
				snort::dtByteCount(regionCi.dataType) * regionCi.elementCount
			),
			.image = image,
			.texture = texture,
		};
		device.currentMemoryRegion.push_back(regionInfo);
	}

	return SnortDevice {
		.handle = (u64)(uintptr_t)(new snort::Device(std::move(device)))
	};
}

// --

void snort_deviceDestroy(
	SnortDevice * device
) {
	if (device == nullptr || device->handle == 0) { return; }
	snort::Device * devPtr = (snort::Device *)(uintptr_t)(device->handle);
	delete devPtr;
	device->handle = 0;
}

// --

bool snort_shouldQuit([[maybe_unused]] SnortDevice const device)
{
	return WindowShouldClose();
}

// --

bool snort_startFrame(SnortDevice const deviceHandle)
{
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);
	BeginDrawing();
	ClearBackground(DARKGRAY);
	snort::displayFrameBegin(device);
	return !device.paused;
}

// --

void snort_endFrame(
	SnortDevice const deviceHandle,
	SnortMemoryRegion const * memoryRegions
) {
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);

	if (device.paused) {
		snort::displayFrameEnd(device);
		return;
	}

	// -- increment instruction count
	++ device.instructionCount;

	// -- delta frame memory
	if (device.frameHistory.size() > 5u) {
		device.frameHistory.erase(device.frameHistory.begin());
	}
	auto & frameDelta = device.frameHistory.emplace_back();
	frameDelta.memoryRegionDeltas.resize(device.currentMemoryRegion.size());
	for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
		frameDelta.memoryRegionDeltas[it] = (
			::storeFrameDelta(device, memoryRegions, it)
		);
	}

	// -- then store actual frame memory
	for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
		auto & regionInfo = device.currentMemoryRegion[it];
		auto & referenceData = memoryRegions[it].data;
		memcpy(
			regionInfo.currentData.data(),
			referenceData,
			regionInfo.byteCount
		);
	}

	// -- display
	snort::displayFrameEnd(device);
}
