// logs the emulator deltas into a file for comparison with other emulators

#include "device.hpp"

namespace {

// a single delta of memory change
struct LogEmuMemoryRegionDiff {
	size_t byteOffset;
	std::vector<uint8_t> byteData;
};

struct LogEmuMemoryDiff {
	// since some emulators might run at different speeds, log the
	// instruction index.
	int64_t instructionIndex;
	std::vector<LogEmuMemoryRegionDiff> regionDiffs;
};

// file structure:
// [
// 	i64 instructionIndex,
// 	usize region-diff count,
// 	[usize offset, usize count, byte data ...] * region-diff count,
// 	...
// ]

} // namespace

//
