#include <snort/snort-ui.h>

#include <raylib.h>
#include <imgui.h>
#include <vector>

namespace gui {
	void displayMemoryRegion(
		SnortMemoryRegionCreateInfo const & regionInfo,
		u8 const * const regionData
	);

	void displayMemoryTexture(
		SnortMemoryRegionCreateInfo const & regionInfo,
		u8 const * const regionData
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
	size_t const regions,
	SnortMemoryRegionCreateInfo const * const regionInfo,
	u8 const * const * const regionData
) {
	for (size_t it = 0; it < regions; ++ it) {
		auto const & info = regionInfo[it];
		ImGui::Begin(info.label);
		gui::displayMemoryRegion(info, regionData[it]);
		ImGui::End();
	}
}

// --

void gui::displayMemoryRegion(
	SnortMemoryRegionCreateInfo const & regionInfo,
	u8 const * const regionData
) {
	// display texture if image data type
	if (
		   regionInfo.dataType == kSnortDt_r8
		|| regionInfo.dataType == kSnortDt_rgba8
	) {
		gui::displayMemoryTexture(regionInfo, regionData);
		return;
	}

	size_t const byteStride = snort_dtByteCount(regionInfo.dataType);

	// display memory region based on data type for the specified row
	for (size_t it = 0; it < regionInfo.elementCount; ++it) {
		uint8_t const * const regionPtr = (
			(uint8_t const *)regionData + it * byteStride
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
			   imageTexture.image.width == width
			&& imageTexture.image.height == height
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
	u8 const * const regionData
) {
	gui::ImageTexture const image = gui::findOrCreateImageTexture(regionInfo);
	// display as texture, but first update the image data
	if (regionInfo.dataType == kSnortDt_r8) {
		// single channel image
		for (int y = 0; y < image.image.height; ++ y) {
			for (int x = 0; x < image.image.width; ++ x) {
				size_t index = y * image.image.width + x;
				u8 value = regionData[index];
				((u8 *)image.image.data)[index * 4 + 0] = value;
				((u8 *)image.image.data)[index * 4 + 1] = value;
				((u8 *)image.image.data)[index * 4 + 2] = value;
				((u8 *)image.image.data)[index * 4 + 3] = 255u;
			}
		}
		UpdateTexture(image.texture, image.image.data);
	}
	else if (regionInfo.dataType == kSnortDt_rgba8) {
		// rgba8 image
		memcpy(
			image.image.data,
			regionData,
			image.image.width * image.image.height * 4
		);
		UpdateTexture(image.texture, image.image.data);
	}
	ImGui::Image(
		(void *)(uintptr_t)image.texture.id,
		ImVec2(
			(float)image.image.width,
			(float)image.image.height
		)
	);
}
