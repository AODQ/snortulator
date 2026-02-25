#include "device.hpp"

#include <ctime>
#include <snort/snort-ui.h>

#include <cstring>
#include <string_view>

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
	printf("recording file path: %s\n", ci->recordingFilepath);

	// -- load device
	snort::Device device = {
		.name = std::string(ci->name),
		.recordingFilepath = std::string(ci->recordingFilepath),
		.commonInterface = ci->commonInterface,
		.currentMemoryRegion = {},
	};

	// -- initialize raylib + imgui
	snort_displayInitialize();

	// -- register memory regions
	for (size_t it = 0; it < ci->memoryRegionCount; ++ it) {
		auto const & regionCi = ci->memoryRegions[it];
		size_t const width = regionCi.elementDisplayRowStride;
		size_t const height = (
			regionCi.elementDisplayRowStride == 0
			? 1
			: regionCi.elementCount / regionCi.elementDisplayRowStride
		);
		Image image {};
		Texture2D texture {};
		if (
			   regionCi.dataType == kSnortDt_r1
			|| regionCi.dataType == kSnortDt_r8
		) {
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

	// -- parse command line args
	for (int32_t it = 1; it < ci->argc; ++ it) {
		std::string_view const arg = ci->argv[it];
		if (arg == "--start-recording" && it + 1 < ci->argc) {
			std::string_view const val = ci->argv[++ it];
			if (val == "true") {
				device.isRecording = true;
				device.isRecordingFirstFrame = true;
				device.paused = false;
				device.recordingFile = (
					SnortFs::replayRecorder_open(
						device.recordingFilepath.c_str(),
						/*commonInterface=*/ device.commonInterface,
						/*instructionOffset=*/ device.instructionCount,
						/*regionCount=*/ device.currentMemoryRegion.size(),
						/*regionCreateInfo=*/ (
							device.memoryRegionCreateInfo.data()
						)
					)
				);
			}
		}
		else if (
			arg == "--target-instruction-count" && it + 1 < ci->argc
		) {
			device.targetInstructionCount = std::stoi(ci->argv[++ it]);
		}
		else if (
			arg == "--close-once-done-recording" && it + 1 < ci->argc
		) {
			std::string_view const val = ci->argv[++ it];
			if (val == "true") {
				device.closeOnceDoneRecording = true;
			}
		}
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
	snort::Device * devPtr = (snort::Device *)(uintptr_t)(device.handle);
	if (devPtr->closeOnceDoneRecording && !devPtr->isRecording) {
		return true;
	}
	return WindowShouldClose();
}

// --

u64 snort_startFrame(
	SnortDevice const deviceHandle,
	SnortMemoryRegion const * memoryRegions
)
{
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);
	snort_displayFrameBegin();

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

	snort_displayMemory(
		device.commonInterface,
		device.currentMemoryRegion.size(),
		device.memoryRegionCreateInfo.data(),
		(u8 const * const *)memoryRegions,
		nullptr
	);

	// -- return number of frames to run
	if (device.paused) {
		return 0u;
	}
	if (device.step) {
		device.step = false;
		return 1u;
	}
	if (device.isRecording) {
		return 100u;
	}
	return 1u;
}

// --

void snort_updateFrame(
	SnortDevice const deviceHandle,
	SnortMemoryRegion const * memoryRegions
) {
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);

	// -- recording
	if (!device.paused && device.isRecording) {
		// if reached target instruction offset, return
		if (
			device.instructionCount >= (size_t)device.targetInstructionCount
		) {
			return;
		}
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

	// -- increment instruction count
	++ device.instructionCount;
}

// --

void snort_endFrame(SnortDevice const deviceHandle) {
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);

	if (device.step) {
		// if stepping, pause after one frame
		device.paused = true;
	}
	// -- imgui updates
	{
		ImGui::Begin("configuration");
		ImGui::Checkbox("pause", &device.paused);
		ImGui::SameLine();
		if (ImGui::Button("step")) {
			device.paused = false;
			device.step = true;
		}
		if (device.isRecording) {
			ImGui::Text(
				"recording, %zu / %d",
				device.instructionCount,
				device.targetInstructionCount
			);
		}
		else if (device.instructionCount == 0u) {
			// allow user to start recording on first frame, for now
			// in future they can pick an offset and total count
			ImGui::Text("target instruction offset");
			ImGui::InputInt(
				"##target instruction offset",
				&device.targetInstructionCount
			);
			if (ImGui::Button("Record")) {
				device.recordingFile = (
					SnortFs::replayRecorder_open(
						device.recordingFilepath.c_str(),
						/*commonInterface=*/ device.commonInterface,
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
				}
				device.paused = false;
			}
		}
		ImGui::End();
	}

	// -- pause check
	if (device.paused) {
		snort_displayFrameEnd();
		return;
	}

	// -- close if reached target instruction offset
	if (
		device.isRecording
		&& device.instructionCount >= (size_t)device.targetInstructionCount
	) {
		SnortFs::replayRecorder_close(device.recordingFile);
		device.isRecording = false;
		printf(
			"stopped recording at instruction offset %zu\n",
			device.instructionCount
		);
		device.paused = true;
	}

	// -- display
	snort_displayFrameEnd();
}
