#include <snort/snort-ui.h>

#include "common-interface.hpp"

#include <raylib.h>
#include <imgui.h>

#include <cmath>
#include <string>
#include <unordered_map>
#include <vector>

namespace gui {
	void displayMemoryRegion(
		SnortMemoryRegionCreateInfo const & regionInfo,
		u8 const * const regionData,
		u8 const * const optRegionDataCmp
	);

	void displayMemoryTexture(
		SnortMemoryRegionCreateInfo const & regionInfo,
		u8 const * const regionData,
		u8 const * const optRegionDataCmp = nullptr
	);

	void displayDeviceCommon(
		SnortCommonInterface commonInterface,
		size_t regions,
		SnortMemoryRegionCreateInfo const * regionInfo,
		u8 const * const * regionData,
		u8 const * const * optRegionDataCmp
	);

	struct ImageTexture {
		Image image;
		Texture2D texture;
		SnortDt dataType;
	};
	ImageTexture findOrCreateImageTexture(
		SnortMemoryRegionCreateInfo const & regionInfo
	);
}

// --

void snort_displayInitialize() {
	SetTraceLogLevel(LOG_ERROR);
	InitWindow(1200, 600, "snort-ui");
	SetTargetFPS(60);
	rlImGuiSetup(true);
	ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_DockingEnable;
}

// --

void snort_displayDestroy() {
	rlImGuiShutdown();
	CloseWindow();
}

// --

void snort_displayFrameBegin() {
	BeginDrawing();
	ClearBackground(DARKGRAY);
	rlImGuiBegin();

	ImGui::DockSpaceOverViewport();
}

// --

void snort_displayFrameEnd() {
	rlImGuiEnd();
	EndDrawing();
}

// --

void snort_displayMemory(
	SnortCommonInterface const commonInterface,
	size_t const regions,
	SnortMemoryRegionCreateInfo const * const regionInfo,
	u8 const * const * const regionData,
	u8 const * const * const optRegionDataCmp
) {
	for (size_t it = 0; it < regions; ++ it) {
		auto const & info = regionInfo[it];
		ImGui::Begin(info.label);
		u8 const * const cmpData = (
			optRegionDataCmp != nullptr
			? optRegionDataCmp[it]
			: nullptr
		);
		gui::displayMemoryRegion(info, regionData[it], cmpData);
		ImGui::End();
	}

	gui::displayDeviceCommon(
		commonInterface, regions, regionInfo, regionData, optRegionDataCmp
	);
}

// --

void gui::displayMemoryRegion(
	SnortMemoryRegionCreateInfo const & regionInfo,
	u8 const * const regionData,
	u8 const * const optRegionDataCmp
) {
	// display texture if image data type
	if (
		   regionInfo.dataType == kSnortDt_r1
		|| regionInfo.dataType == kSnortDt_r8
		|| regionInfo.dataType == kSnortDt_rgba8
	) {
		gui::displayMemoryTexture(regionInfo, regionData, optRegionDataCmp);
		return;
	}

	// display debug string if string data type
	if (regionInfo.dataType == kSnortDt_string) {
		ImColor textColor = ImGui::GetStyleColorVec4(ImGuiCol_Text);
		if (optRegionDataCmp != nullptr) {
			if (
				strcmp((char const *)regionData, (char const *)optRegionDataCmp)
				!= 0
			) {
				textColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
			}
		}
		ImGui::TextColored(textColor, "%s", (char const *)regionData);
		return;
	}

	size_t const byteStride = snort_dtByteCount(regionInfo.dataType);

	if (regionInfo.elementDisplayRowStride != 0) {
		ImGui::Text("[0]");
		ImGui::SameLine();
	}

	// display memory region based on data type for the specified row
	for (size_t it = 0; it < regionInfo.elementCount; ++it) {
		uint8_t const * const regionPtr = (
			(uint8_t const *)regionData + it * byteStride
		);
		ImColor textColor = ImGui::GetStyleColorVec4(ImGuiCol_Text);
		// compare memory, if mismatch then color red
		if (optRegionDataCmp != nullptr) {
			uint8_t const * const cmpPtr = (
				(uint8_t const *)optRegionDataCmp + it * byteStride
			);
			if (memcmp(regionPtr, cmpPtr, byteStride) != 0) {
				textColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
			}
		}
		// look for it in frame history, rolling back the data
		#define DtDisplay(type, formatStr) \
			case kSnortDt_##type: { \
				type const * const dataPtr = (type const *)regionPtr; \
				ImGui::TextColored(textColor, formatStr, (type)*dataPtr); \
				break; \
			}
		switch (regionInfo.dataType) {
			DtDisplay(u8, "0x%02X")
			DtDisplay(u16, "0x%03x")
			DtDisplay(u32, "0x%08X")
			DtDisplay(u64, "0x%016lX")
			DtDisplay(i8, "0x%02X")
			DtDisplay(i16, "0x%03x")
			DtDisplay(i32, "0x%08X")
			DtDisplay(i64, "0x%016lX")
			DtDisplay(f32, "%.3f")
			default: {
				ImGui::Text("Incompatible data type");
				break;
			}
		}
		// check for same line
		if (
			   regionInfo.elementDisplayRowStride != 0
			&& (it + 1) % regionInfo.elementDisplayRowStride != 0
		) {
			ImGui::SameLine();
		}
		// print element index unless it's the last element
		else if (it != regionInfo.elementCount - 1) {
			// new line, print the element index for the next line
			ImGui::Text("[%04x]", (u32)(it + 1));
			ImGui::SameLine();
		}
	}
}

// --

gui::ImageTexture gui::findOrCreateImageTexture(
	SnortMemoryRegionCreateInfo const & regionInfo
) {
	static std::vector<ImageTexture> imageTextures;
	auto const width = regionInfo.elementDisplayRowStride;
	auto const height = (
		regionInfo.elementCount / regionInfo.elementDisplayRowStride
	);
	// TODO will need to add some logic to not re-use a texture multiple
	// times per frame
	for (auto & imageTexture : imageTextures) {
		if (
			   imageTexture.image.width == static_cast<i32>(width)
			&& imageTexture.image.height == static_cast<i32>(height)
			&& imageTexture.dataType == regionInfo.dataType
		) {
			return imageTexture;
		}
	}

	Image image = GenImageColor(width, height, BLACK);
	Texture2D texture = LoadTextureFromImage(image);
	ImageTexture imageTexture = {
		.image = image,
		.texture = texture,
		.dataType = regionInfo.dataType,
	};
	imageTextures.emplace_back(imageTexture);
	return imageTexture;
}

// --

void gui::displayMemoryTexture(
	SnortMemoryRegionCreateInfo const & regionInfo,
	u8 const * const regionData,
	u8 const * const optRegionDataCmp
) {
	struct ImageInfo {
		float zoom {1.0};
		bool compareMode {true};
	};
	static std::unordered_map<std::string, ImageInfo> imageInfoMap;
	auto & imageInfo = imageInfoMap[regionInfo.label];
	{
		// center controls for image zoom
		ImGui::Text("image controls");
		ImGui::Text("zoom:");
		ImGui::SliderFloat("##zoom", &imageInfo.zoom, 0.1f, 10.0f);
		if (optRegionDataCmp != nullptr) {
			ImGui::Checkbox("compare mode", &imageInfo.compareMode);
		}
		ImGui::Separator();
	}
	gui::ImageTexture const image = gui::findOrCreateImageTexture(regionInfo);
	// display as texture, but first update the image data
	if (regionInfo.dataType == kSnortDt_r1) {
		// binary image
		for (int y = 0; y < image.image.height; ++ y)
		for (int x = 0; x < image.image.width; ++ x) {
			size_t index = y * image.image.width + x;
			u8 const value = regionData[index];
			((u8 *)image.image.data)[index * 4 + 0] = value*255u;
			((u8 *)image.image.data)[index * 4 + 1] = value*255u;
			((u8 *)image.image.data)[index * 4 + 2] = value*255u;
			((u8 *)image.image.data)[index * 4 + 3] = 255u;
			if (imageInfo.compareMode && optRegionDataCmp != nullptr) {
				u8 cmpValue = optRegionDataCmp[index];
				if (value != cmpValue) {
					((u8 *)image.image.data)[index * 4 + 0] = 255u;
					((u8 *)image.image.data)[index * 4 + 1] = 0u;
					((u8 *)image.image.data)[index * 4 + 2] = 0u;
				}
			}
		};
		UpdateTexture(image.texture, image.image.data);
	}
	else if (regionInfo.dataType == kSnortDt_r8) {
		// single channel image
		for (int y = 0; y < image.image.height; ++ y)
		for (int x = 0; x < image.image.width; ++ x) {
			size_t index = y * image.image.width + x;
			u8 value = regionData[index];
			((u8 *)image.image.data)[index * 4 + 0] = value;
			((u8 *)image.image.data)[index * 4 + 1] = value;
			((u8 *)image.image.data)[index * 4 + 2] = value;
			((u8 *)image.image.data)[index * 4 + 3] = 255u;
			if (imageInfo.compareMode && optRegionDataCmp != nullptr) {
				u8 cmpValue = optRegionDataCmp[index];
				value = fabsf((float)value - (float)cmpValue)*10.0f;
				value = (value > 255 ? 255 : value);
			}
		};
		UpdateTexture(image.texture, image.image.data);
	}
	else if (regionInfo.dataType == kSnortDt_rgba8) {
		// rgba8 image
		if (!imageInfo.compareMode || optRegionDataCmp == nullptr) {
			memcpy(
				image.image.data,
				regionData,
				image.image.width * image.image.height * 4
			);
		} else {
			for (int y = 0; y < image.image.height; ++y)
			for (int x = 0; x < image.image.width; ++x) {
				float diff = 0.0f;
				for (size_t c = 0; c < 4; ++c) {
					size_t const index = (y * image.image.width + x) * 4 + c;
					diff += (
						fabsf((float)regionData[index] - (float)optRegionDataCmp[index])
					);
				}
				diff = (diff / 4.0f) * 10.0f;
				diff = (diff > 255.0f ? 255.0f : diff);
				for (size_t c = 0; c < 4; ++c) {
					size_t const index = (y * image.image.width + x) * 4 + c;
					((u8 *)image.image.data)[index] = (u8)diff;
				}
			};
		}
		UpdateTexture(image.texture, image.image.data);
	}
	// horizontal alignment
	{
		ImVec2 const availSize = ImGui::GetContentRegionAvail();
		ImVec2 const imageSize = ImVec2(
			(float)image.image.width  * imageInfo.zoom,
			(float)image.image.height * imageInfo.zoom
		);
		if (availSize.x > imageSize.x) {
			ImGui::SetCursorPosX((availSize.x - imageSize.x) * 0.5f);
		}

		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10.0f);
	}
	ImGui::Image(
		(void *)(uintptr_t)image.texture.id,
		ImVec2(
			(float)image.image.width  * imageInfo.zoom,
			(float)image.image.height * imageInfo.zoom
		)
	);
}

// --

void gui::displayDeviceCommon(
	SnortCommonInterface commonInterface,
	size_t regions,
	SnortMemoryRegionCreateInfo const * regionInfo,
	u8 const * const * regionData,
	u8 const * const * optRegionDataCmp
)
{
	switch (commonInterface) {
		case kSnortCommonInterface_chip8: {
			gui::displayDeviceChip8(
				regions, regionInfo, regionData, optRegionDataCmp
			);
			break;
		}
		case kSnortCommonInterface_custom: {
			ImGui::Text("common interface: custom");
			break;
		}
	}
}
