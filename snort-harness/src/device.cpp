#include "device.hpp"

#include "imgui-display.hpp"

#include <cstring>

namespace {

std::vector<snort::MemoryRegionDelta> storeFrameDelta(
	snort::Device & device,
	bool const recordToDevice,
	SnortMemoryRegion const * memoryRegions,
	size_t const regionIndex
) {
	std::vector<snort::MemoryRegionDelta> delta;
	// the recording delta is different since it supports forwarding data,
	//   the local delta is for rolling back data
	std::vector<SnortFs::MemoryRegionDiffRecord> recordDelta;
	std::vector<std::vector<uint8_t>> recordDeltaData;
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
			if (recordToDevice) {
				recordDelta.emplace_back(
					SnortFs::MemoryRegionDiffRecord {
						.byteOffset = startByteDiff,
						.byteCount = (byteIt - startByteDiff),
						.data = {},
					}
				);
				recordDeltaData.emplace_back(
					std::vector<uint8_t>(
						&referenceData[startByteDiff],
						&referenceData[byteIt]
					)
				);
			}
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
	if (recordToDevice) {
		// store the data at end to avoid ptr movement from reallocs
		for (size_t it = 0; it < recordDelta.size(); ++ it) {
			recordDelta[it].data = recordDeltaData[it].data();
		}
		// record delta for current region and current instruction into file
		SnortFs::replayRecord(
			device.recordingFile,
			recordDelta.size(),
			recordDelta.data()
		);
	}
	return delta;
}

} // namespace

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
				snort_dtByteCount(regionCi.dataType) * regionCi.elementCount
			),
			.byteStride = snort_dtByteCount(regionCi.dataType),
			.elementCount = regionCi.elementCount,
			.elementDisplayRowStride = regionCi.elementDisplayRowStride,
			.label = std::string(regionCi.label),
			.currentData = std::vector<uint8_t>(
				snort_dtByteCount(regionCi.dataType) * regionCi.elementCount
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

	// rlImGuiShutdown();
	CloseWindow();
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

	// -- recording
	bool const shouldRecordDuringDelta = (
		device.isRecording
		&& !device.isRecordingFirstFrame
	);
	// if first frame recording, write all memory region data as diff
	if (device.isRecording) {
		if (device.isRecordingFirstFrame) {
			for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
				auto & regionInfo = device.currentMemoryRegion[it];
				auto & referenceData = memoryRegions[it].data;
				SnortFs::MemoryRegionDiffRecord diffRecord = {
					.byteOffset = 0u,
					.byteCount = regionInfo.byteCount,
					.data = referenceData,
				};
				SnortFs::replayRecord(
					device.recordingFile,
					1u,
					&diffRecord
				);
			}
		}
	}

	// -- local delta frame memory
	if (device.frameHistory.size() > 5u) {
		device.frameHistory.erase(device.frameHistory.begin());
	}
	auto & frameDelta = device.frameHistory.emplace_back();
	frameDelta.memoryRegionDeltas.resize(device.currentMemoryRegion.size());
	for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
		frameDelta.memoryRegionDeltas[it] = (
			::storeFrameDelta(device, shouldRecordDuringDelta, memoryRegions, it)
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

	// -- increment instruction count
	++ device.instructionCount;
}
