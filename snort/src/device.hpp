#pragma once

#include <snort/snort.hpp>
#include <snort-replay/fs.hpp>

// below only for initialization
#include <raylib.h>

#include <vector>
#include <string>

// -----------------------------------------------------------------------------
// -- snort device private impl ------------------------------------------------
// -----------------------------------------------------------------------------

namespace snort {

struct MemoryRegionDelta {
	u64 byteOffset;
	std::vector<uint8_t> deltaData;
};

struct FrameDelta {
	std::vector<std::vector<MemoryRegionDelta>> memoryRegionDeltas;
};

struct MemoryRegionInfo {
	SnortDt const dataType;
	size_t const byteCount;
	size_t const byteStride;
	size_t const elementCount;
	size_t const elementDisplayRowStride;
	std::string const label;
	std::vector<uint8_t> currentData;
	Image image {}; // for image data types
	Texture2D texture {};
};

struct Device {
	std::string const name;
	size_t instructionCount { 0 };
	std::vector<FrameDelta> frameHistory;
	std::vector<MemoryRegionInfo> currentMemoryRegion;
	u64 rngSeed { 1234u };
	mutable int32_t displayRelativeFrame { 0 };
	mutable bool paused { false };

	mutable bool isRecording { false };
	// lets device know to diff everything first frame
	mutable bool isRecordingFirstFrame { true };
	mutable SnortFs::ReplayFileRecorder recordingFile { 0 };
};

size_t dtByteCount(SnortDt const dt);

} // namespace snort
