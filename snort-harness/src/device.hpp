#pragma once

#include <snort-harness/snort-harness.h>

#include <snort/snort.h>
#include <snort-replay/fs.hpp>

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

struct MemoryRegionInfo {
	SnortDt const dataType;
	size_t const byteCount;
	size_t const byteStride;
	size_t const elementCount;
	size_t const elementDisplayRowStride;
	std::string const label;
	std::vector<uint8_t> currentData;
};

struct Device {
	std::string const name;
	std::string const recordingFilepath;
	SnortCommonInterface commonInterface { kSnortCommonInterface_custom };
	std::vector<MemoryRegionInfo> currentMemoryRegion;
	std::vector<SnortMemoryRegionCreateInfo> memoryRegionCreateInfo;

	// -- emulator state
	u64 rngSeed { 1234u };
	size_t instructionCount { 0 };
	mutable bool paused { true };
	mutable bool step { false };

	// -- recording
	mutable bool isRecording { false };
	// lets device know to diff everything first frame
	mutable bool isRecordingFirstFrame { true };
	mutable SnortFs::ReplayFileRecorder recordingFile { 0 };
	mutable i32 targetInstructionCount { 10 };
	mutable bool closeOnceDoneRecording { false };
};

} // namespace snort
