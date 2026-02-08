#pragma once

#include <cstddef>
#include <cstdint>

// a simple file system that reads/writes replays into binary files
// The file just stores diffs of memory between each instruction
/*
	Format:
	- magic number (8 bytes)
	- instruction offset (8 bytes)
	- instruction count (8 bytes)
	- region count (8 bytes)
	- per-instruction: (implicit)
		- per memory region: (implicit)
			- diff count (8 bytes)
			- per diff:
				- byte offset (8 bytes)
				- byte count (8 bytes)
				- memory region data (byte count bytes)
	- magic number (8 bytes, to verify instructions were read correctly)
*/

namespace SnortFs {

	// -- replay ----------------------------------------------------------------

	struct MemoryRegionDiff {
		uint64_t byteOffset;
		uint64_t byteCount;
		uint8_t * data;
	};

	struct ReplayFile { uint64_t handle; };

	ReplayFile replayOpen(char const * const filepath);
	void replayClose(ReplayFile const file);

	uint64_t replayInstructionOffset(ReplayFile const file);
	uint64_t replayInstructionCount(ReplayFile const file);
	uint64_t replayRegionCount(ReplayFile const file);

	size_t replayInstructionDiffCount(
		ReplayFile const file,
		size_t const instructionIndex,
		size_t const regionIndex
	);

	MemoryRegionDiff * replayInstructionDiff(
		ReplayFile const file,
		size_t const instructionIndex,
		size_t const regionIndex
	);

	// -- recording -------------------------------------------------------------

	struct ReplayFileRecorder { uint64_t handle; };

	ReplayFileRecorder replayRecordOpen(
		char const * const filepath,
		uint64_t const instructionOffset,
		uint64_t const regionCount
	);
	void replayRecordClose(ReplayFileRecorder const recorder);

	struct MemoryRegionDiffRecord {
		uint64_t byteOffset;
		uint64_t byteCount;
		uint8_t const * data;
	};

	// records the memory region diffs, sequentially. so start at first
	//   instruction, first region, then second region, etc until second instr
	//   and first region, etc.
	// The first frame should probably capture the entire memory region as
	//   a single diff so that it's all populated with data
	void replayRecord(
		ReplayFileRecorder const recorder,
		size_t const diffCount,
		MemoryRegionDiffRecord const * diffs
	);
}
