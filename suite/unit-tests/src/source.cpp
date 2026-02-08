#include <snort/snort.h>

#include <snort-harness/snort-harness.h>
#include <snort-replay/fs.hpp>

#include <string>
#include <vector>

#define Assert(x) \
	if (!(x)) { \
		printf("assertion failed: %s (%s:%d)\n", #x, __FILE__, __LINE__); \
		std::abort(); \
	}

void replayTests() {
	// -- record
	SnortFs::ReplayFileRecorder file = (
		SnortFs::replayRecordOpen(
			"test-replay.rpl",
			/*instructionOffset=*/ 0,
			/*regionCount=*/ 2
		)
	);
	Assert(file.handle != 0);

	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 4, .data = (uint8_t const *)"test" },
			{ .byteOffset = 4, .byteCount = 4, .data = (uint8_t const *)"data" },
		};
		SnortFs::replayRecord(file, 1, diffs.data());
		SnortFs::replayRecord(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"he" },
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"lo" },
		};
		SnortFs::replayRecord(file, 1, diffs.data());
		SnortFs::replayRecord(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"wo" },
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"rl" },
		};
		SnortFs::replayRecord(file, 1, diffs.data());
		SnortFs::replayRecord(file, 1, diffs.data()+1);
	}
	SnortFs::replayRecordClose(file);
	Assert(file.handle == 0);

	// -- playback
	SnortFs::ReplayFile replayFile = SnortFs::replayOpen("test-replay.rpl");
	Assert(replayFile.handle != 0);
	Assert(SnortFs::replayInstructionOffset(replayFile) == 0);
	Assert(SnortFs::replayInstructionCount(replayFile) == 3);
	Assert(SnortFs::replayRegionCount(replayFile) == 2);
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 0, 0);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 4);
		Assert(memcmp(diffs[0].data, "test", 4) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 0, 1);
		Assert(diffs[0].byteOffset == 4);
		Assert(diffs[0].byteCount == 4);
		Assert(memcmp(diffs[0].data, "data", 4) == 0);
	}

	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 1, 0);
		Assert(diffs[0].byteOffset == 2);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "he", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 1, 1);
		Assert(diffs[0].byteOffset == 2);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "lo", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 2, 0);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "wo", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replayInstructionDiff(replayFile, 2, 1);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "rl", 2) == 0);
	}

	SnortFs::replayClose(replayFile);
	Assert(replayFile.handle == 0);
}

int32_t main() {
	// replay tests
	replayTests();
	// device creation
	SnortDevice device = []() {
		std::vector<SnortMemoryRegionCreateInfo> memoryRegions = {
			{
				.dataType = kSnortDt_u8,
				.elementCount = 8,
				.elementDisplayRowStride = 1u,
				.label = "region-registers",
			},
			{
				.dataType = kSnortDt_u16,
				.elementCount = 128u,
				.elementDisplayRowStride = 16u,
				.label = "region-memory",
			},
			{
				.dataType = kSnortDt_rgba8,
				.elementCount = 64u * 64u,
				.elementDisplayRowStride = 64u,
				.label = "region-display",
			},
		};

		SnortDeviceCreateInfo const deviceCreateInfo = {
			.name = "snorter test device",
			.memoryRegions = memoryRegions.data(),
			.memoryRegionCount = memoryRegions.size(),
		};

		return snort_deviceCreate(&deviceCreateInfo);
	}();

	std::vector<uint8_t> registers(/*__n=*/ 8, /*__value=*/ 0);
	std::vector<uint16_t> memory(/*__n=*/ 128, /*__value=*/ 0);
	std::vector<uint8_t> display(/*__n=*/ 64 * 64 * 4, /*__value=*/ 0);

	int fc = 0;
	int fcDir = 1;

	// main loop
	while (!snort_shouldQuit(device)) {
		// -- update registers
		if (snort_startFrame(device)) {
			registers[0] += 1;
			registers[1] += 2;
			registers[2] += 4;
		}

		// -- update breathing texture
		fc = (fc + fcDir);
		if (fc > 100 || fc < 1) fcDir *= -1;
		for (size_t x = 0; x < 64; ++x)
		for (size_t y = 0; y < 64; ++y) {
			size_t index = (y * 64 + x) * 4;
			display[index + 0] = ((x+fc) % 256);
			display[index + 1] = ((y+fc) % 256);
			display[index + 2] = ((x + y) % 256);
			display[index + 3] = 255u;
		};

		// -- update random memory
		memory[0] = snort_rngU64(device);
		memory[1] = snort_rngU64(device);
		memory[2] = snort_rngU64(device);
		memory[3] = snort_rngU64(device);

		snort_endFrame(
			device,
			(SnortMemoryRegion const []) {
				{ registers.data() },
				{ (u8 const *)memory.data() },
				{ display.data() },
			}
		);
	}

	snort_deviceDestroy(&device);
	return 0;
}
