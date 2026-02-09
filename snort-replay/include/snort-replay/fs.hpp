#pragma once

#include <snort/snort.h>

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
	- per-region: (implicit)
		- data-type (8 bytes)
		- element count (8 bytes)
		- element display row stride (8 bytes)
		- label length (8 bytes)
		- label (label length bytes)
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

	ReplayFile replay_open(char const * const filepath);
	void replay_close(ReplayFile & file);

	uint64_t replay_instructionOffset(ReplayFile const file);
	uint64_t replay_instructionCount(ReplayFile const file);
	uint64_t replay_regionCount(ReplayFile const file);

	SnortMemoryRegionCreateInfo const * replay_regionInfo(
		ReplayFile const file
	);

	size_t replay_instructionDiffCount(
		ReplayFile const file,
		size_t const instructionIndex,
		size_t const regionIndex
	);

	MemoryRegionDiff * replay_instructionDiff(
		ReplayFile const file,
		size_t const instructionIndex,
		size_t const regionIndex
	);

	// -- recording -------------------------------------------------------------

	struct ReplayFileRecorder { uint64_t handle; };

	ReplayFileRecorder replayRecorder_open(
		char const * const filepath,
		uint64_t const instructionOffset,
		uint64_t const regionCount,
		SnortMemoryRegionCreateInfo const * regionCreateInfo
	);
	void replayRecorder_close(ReplayFileRecorder & recorder);

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
	void replayRecorder_recordInstruction(
		ReplayFileRecorder & recorder,
		size_t const diffCount,
		MemoryRegionDiffRecord const * diffs
	);
}
