#include "imgui-display.hpp"

#include <ctime>
#include <imgui.h>
#include <rlImGui.h>

namespace gui {
	void displayMemory(snort::Device const & device);
	void displayMemoryRegion(
		snort::Device const & device,
		size_t const frameIndex,
		size_t const regionIndex
	);
	void displayMemoryTexture(
		snort::Device const & device,
		snort::MemoryRegionInfo const & regionInfo,
		std::vector<uint8_t> const & regionData
	);
}

// -----------------------------------------------------------------------------
// -- public api impl ----------------------------------------------------------
// -----------------------------------------------------------------------------

// --

void snort::displayInitialize(snort::Device const & device) {
	rlImGuiSetup(true);
	ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_DockingEnable;
}

// --

void snort::displayFrameBegin(snort::Device const & device) {
	BeginDrawing();
	ClearBackground(DARKGRAY);
	rlImGuiBegin();

	ImGui::DockSpaceOverViewport();

	ImGui::Begin("stats");
	ImGui::Text("FPS: %d", GetFPS());
	ImGui::End();
}

// --

void snort::displayFrameEnd(snort::Device const & device) {
	gui::displayMemory(device);
	rlImGuiEnd();
	EndDrawing();
}

// -----------------------------------------------------------------------------
// -- private api impl ---------------------------------------------------------
// -----------------------------------------------------------------------------

void gui::displayMemory(snort::Device const & device) {

	ImGui::Begin("configuration");
	ImGui::SliderInt(
		"relative frame",
		&device.displayRelativeFrame,
		/*v_min=*/ 0,
		/*v_max=*/ (int)device.frameHistory.size() - 1
	);
	ImGui::Checkbox("pause", &device.paused);
	if (device.isRecording) {
		ImGui::Text("recording...");
	}
	else if (ImGui::Button("Record")) {
		// TODO file picker
		char filepath[256];
		snprintf(filepath, 256, "recording-%zu.rpl", time(NULL));
		device.recordingFile = (
			SnortFs::replayRecordOpen(
				filepath,
				/*instructionOffset=*/ device.instructionCount,
				/*regionCount=*/ device.currentMemoryRegion.size()
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

	for (size_t it = 0; it < device.currentMemoryRegion.size(); ++it) {
		auto const & info = device.currentMemoryRegion[it];
		ImGui::Begin(info.label.c_str());
		gui::displayMemoryRegion(device, device.displayRelativeFrame, it);
		ImGui::End();
	}
}

// --

void gui::displayMemoryRegion(
	snort::Device const & device,
	size_t const frameIndex,
	size_t const regionIndex
) {
	auto const & regionInfo = device.currentMemoryRegion[regionIndex];

	ImGui::Begin(regionInfo.label.c_str());

	// roll back the memory
	std::vector<uint8_t> regionData = regionInfo.currentData;
	auto & frameHistory = (
		device.frameHistory[device.frameHistory.size() - 1 - frameIndex]
	);
	for (auto & delta : frameHistory.memoryRegionDeltas[regionIndex]) {
		printf("applying delta for region %zu, byte offset %zu, data size %zu\n",
			regionIndex, delta.byteOffset, delta.deltaData.size()
		);
		for (size_t it = 0; it < delta.deltaData.size(); ++ it) {
			regionData[delta.byteOffset + it] = delta.deltaData[it];
		}
	}

	// display texture if image data type
	if (
		   regionInfo.dataType == kSnortDt_r8
		|| regionInfo.dataType == kSnortDt_rgba8
	) {
		gui::displayMemoryTexture(device, regionInfo, regionData);
		ImGui::End();
		return;
	}

	// display memory region based on data type for the specified row
	for (size_t it = 0; it < regionInfo.elementCount; ++it) {
		uint8_t const * const regionPtr = (
			regionData.data() + it * regionInfo.byteStride
		);
		// look for it in frame history, rolling back the data
		#define DtDisplay(type, formatStr) \
			case kSnortDt_##type: { \
				type const * const dataPtr = (type const *)regionPtr; \
				ImGui::Text(formatStr, *dataPtr); \
				break; \
			}
		switch (regionInfo.dataType) {
			DtDisplay(u8, "0x%02X")
			DtDisplay(u16, "%u")
			DtDisplay(u32, "%u")
			DtDisplay(u64, "%zu")
			DtDisplay(i8, "%d")
			DtDisplay(i16, "%d")
			DtDisplay(i32, "%d")
			DtDisplay(i64, "%ld")
			DtDisplay(f32, "%.3f")
			default: {
				ImGui::Text("Incompatible data type");
				break;
			}
		}
	}

	ImGui::End();
}

// --

void gui::displayMemoryTexture(
	snort::Device const & device,
	snort::MemoryRegionInfo const & regionInfo,
	std::vector<uint8_t> const & regionData
) {
	// display as texture, but first update the image data
	if (regionInfo.dataType == kSnortDt_r8) {
		// single channel image
		for (int y = 0; y < regionInfo.image.height; ++ y) {
			for (int x = 0; x < regionInfo.image.width; ++ x) {
				size_t index = y * regionInfo.image.width + x;
				u8 value = regionData[index];
				((u8 *)regionInfo.image.data)[index * 4 + 0] = value;
				((u8 *)regionInfo.image.data)[index * 4 + 1] = value;
				((u8 *)regionInfo.image.data)[index * 4 + 2] = value;
				((u8 *)regionInfo.image.data)[index * 4 + 3] = 255u;
			}
		}
		UpdateTexture(regionInfo.texture, regionInfo.image.data);
	}
	else if (regionInfo.dataType == kSnortDt_rgba8) {
		// rgba8 image
		memcpy(
			regionInfo.image.data,
			regionData.data(),
			regionInfo.image.width * regionInfo.image.height * 4
		);
		UpdateTexture(regionInfo.texture, regionInfo.image.data);
	}
	ImGui::Image(
		(void *)(uintptr_t)regionInfo.texture.id,
		ImVec2(
			(float)regionInfo.image.width,
			(float)regionInfo.image.height
		)
	);
}
