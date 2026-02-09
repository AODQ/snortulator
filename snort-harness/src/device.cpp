#include "device.hpp"

#include <ctime>
#include <snort/snort-ui.h>

#include <cstring>

namespace {

void storeFrameDelta(
	snort::Device & device,
	SnortMemoryRegion const * memoryRegions,
	size_t const regionIndex
) {
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

	// store the data at end to avoid ptr movement from reallocs
	for (size_t it = 0; it < recordDelta.size(); ++ it) {
		recordDelta[it].data = recordDeltaData[it].data();
	}
	// record delta for current region and current instruction into file
	SnortFs::replayRecorder_recordInstruction(
		device.recordingFile,
		recordDelta.size(),
		recordDelta.data()
	);
}

} // namespace

// --

SnortDevice snort_deviceCreate(
	SnortDeviceCreateInfo const * const ci
) {
	snort::Device device = {
		.name = std::string(ci->name),
		.currentMemoryRegion = {},
	};

	// -- initialize raylib + imgui
	snort_displayInitialize();

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
		};
		device.currentMemoryRegion.push_back(regionInfo);
	}

	// -- reconstruct create info
	for (size_t it = 0; it < ci->memoryRegionCount; ++ it) {
		auto & region = device.currentMemoryRegion[it];
		device.memoryRegionCreateInfo.emplace_back(SnortMemoryRegionCreateInfo {
			.dataType = region.dataType,
			.elementCount = region.elementCount,
			.elementDisplayRowStride = region.elementDisplayRowStride,
			.label = region.label.c_str(),
		});
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

	snort_displayDestroy();
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
	snort_displayFrameBegin();
	return !device.paused;
}

// --

void snort_endFrame(
	SnortDevice const deviceHandle,
	SnortMemoryRegion const * memoryRegions
) {
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);

	// -- imgui updates
	{
		ImGui::Begin("configuration");
		ImGui::Checkbox("pause", &device.paused);
		if (device.isRecording) {
			if (ImGui::Button("Stop recording")) {
				SnortFs::replayRecorder_close(device.recordingFile);
				device.isRecording = false;
			}
		}
		else if (ImGui::Button("Record")) {
			// TODO file picker
			char filepath[256];
			snprintf(filepath, 256, "recording-%zu.rpl", time(NULL));
			device.recordingFile = (
				SnortFs::replayRecorder_open(
					filepath,
					/*instructionOffset=*/ device.instructionCount,
					/*regionCount=*/ device.currentMemoryRegion.size(),
					/*regionCreateInfo=*/ device.memoryRegionCreateInfo.data()
				)
			);
			if (device.recordingFile.handle == 0) {
				printf("failed to start recording\n");
			}
			else {
				device.isRecording = true;
				device.isRecordingFirstFrame = true;
				printf("started recording to file %s\n", filepath);
			}
		}
		ImGui::End();
	}

	// -- pause check
	if (device.paused) {
		snort_displayMemory(
			device.currentMemoryRegion.size(),
			device.memoryRegionCreateInfo.data(),
			(u8 const * const *)memoryRegions
		);
		snort_displayFrameEnd();
		return;
	}

	// -- recording
	if (device.isRecording) {
		// -- full frame memory
		if (device.isRecordingFirstFrame) {
			for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
				auto & regionInfo = device.currentMemoryRegion[it];
				auto & referenceData = memoryRegions[it].data;
				SnortFs::MemoryRegionDiffRecord diffRecord = {
					.byteOffset = 0u,
					.byteCount = regionInfo.byteCount,
					.data = referenceData,
				};
				SnortFs::replayRecorder_recordInstruction(
					device.recordingFile,
					1u,
					&diffRecord
				);
			}
		}
		// -- local delta frame memory
		else {
			for (size_t it = 0; it < device.currentMemoryRegion.size(); ++ it) {
				::storeFrameDelta(device, memoryRegions, it);
			}
		}
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
	snort_displayMemory(
		device.currentMemoryRegion.size(),
		device.memoryRegionCreateInfo.data(),
		(u8 const * const *)memoryRegions
	);
	snort_displayFrameEnd();

	// -- increment instruction count
	++ device.instructionCount;
}
