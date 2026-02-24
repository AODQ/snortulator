#include <snort/snort.h>

#include <snort-harness/snort-harness.h>
#include <snort-replay/fs.hpp>

#include "imgui.h"

#include <cstring>
#include <string>
#include <vector>

#define Assert(x) \
	if (!(x)) { \
		printf("assertion failed: %s (%s:%d)\n", #x, __FILE__, __LINE__); \
		std::abort(); \
	}

void replayTest1() {
	// -- record
	std::vector<SnortMemoryRegionCreateInfo> regionCreateInfo = {
		{
			.dataType = kSnortDt_u8,
			.elementCount = 8,
			.elementDisplayRowStride = 2u,
			.label = "region-registers",
		},
		{
			.dataType = kSnortDt_u16,
			.elementCount = 2,
			.elementDisplayRowStride = 1u,
			.label = "region-ram",
		},
	};
	SnortFs::ReplayFileRecorder file = (
		SnortFs::replayRecorder_open(
			"test-replay.rpl",
			/*commonInterface=*/ kSnortCommonInterface_custom,
			/*instructionOffset=*/ 0,
			/*regionCount=*/ 2,
			/*regionCreateInfo=*/ regionCreateInfo.data()
		)
	);
	Assert(file.handle != 0);

	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 4, .data = (uint8_t const *)"test" },
			{ .byteOffset = 4, .byteCount = 4, .data = (uint8_t const *)"data" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"he" },
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"lo" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"wo" },
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"rl" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	SnortFs::replayRecorder_close(file);
	Assert(file.handle == 0);

	// -- playback
	SnortFs::ReplayFile replayFile = SnortFs::replay_open("test-replay.rpl");
	Assert(replayFile.handle != 0);
	Assert(SnortFs::replay_instructionOffset(replayFile) == 0);
	Assert(SnortFs::replay_instructionCount(replayFile) == 3);
	Assert(SnortFs::replay_regionCount(replayFile) == 2);
	auto const regionInfo0 = SnortFs::replay_regionInfo(replayFile)[0];
	auto const regionInfo1 = SnortFs::replay_regionInfo(replayFile)[1];
	Assert(regionInfo0.dataType == kSnortDt_u8);
	Assert(regionInfo0.elementCount == 8);
	Assert(regionInfo0.elementDisplayRowStride == 2u);
	Assert(std::string(regionInfo0.label) == "region-registers");
	Assert(regionInfo1.dataType == kSnortDt_u16);
	Assert(regionInfo1.elementCount == 2);
	Assert(regionInfo1.elementDisplayRowStride == 1u);
	Assert(std::string(regionInfo1.label) == "region-ram");
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 0, 0);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 4);
		Assert(memcmp(diffs[0].data, "test", 4) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 0, 1);
		Assert(diffs[0].byteOffset == 4);
		Assert(diffs[0].byteCount == 4);
		Assert(memcmp(diffs[0].data, "data", 4) == 0);
	}

	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 1, 0);
		Assert(diffs[0].byteOffset == 2);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "he", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 1, 1);
		Assert(diffs[0].byteOffset == 2);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "lo", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 2, 0);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "wo", 2) == 0);
	}
	{
		SnortFs::MemoryRegionDiff * diffs = SnortFs::replay_instructionDiff(replayFile, 2, 1);
		Assert(diffs[0].byteOffset == 0);
		Assert(diffs[0].byteCount == 2);
		Assert(memcmp(diffs[0].data, "rl", 2) == 0);
	}

	SnortFs::replay_close(replayFile);
	Assert(replayFile.handle == 0);
}

void replayTest2() {
	// same as replayTest1 just different data, so it can be compared in
	// the view
	// -- record
	std::vector<SnortMemoryRegionCreateInfo> regionCreateInfo = {
		{
			.dataType = kSnortDt_u8,
			.elementCount = 8,
			.elementDisplayRowStride = 2u,
			.label = "region-registers",
		},
		{
			.dataType = kSnortDt_u16,
			.elementCount = 2,
			.elementDisplayRowStride = 1u,
			.label = "region-ram",
		},
	};
	SnortFs::ReplayFileRecorder file = (
		SnortFs::replayRecorder_open(
			"test-replay-2.rpl",
			/*commonInterface=*/ kSnortCommonInterface_custom,
			/*instructionOffset=*/ 0,
			/*regionCount=*/ 2,
			/*regionCreateInfo=*/ regionCreateInfo.data()
		)
	);
	Assert(file.handle != 0);

	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 4, .data = (uint8_t const *)"noop" },
			{ .byteOffset = 4, .byteCount = 4, .data = (uint8_t const *)"frik" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"no" },
			{ .byteOffset = 2, .byteCount = 2, .data = (uint8_t const *)"ob" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	{
		std::vector<SnortFs::MemoryRegionDiffRecord> diffs = {
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"es" },
			{ .byteOffset = 0, .byteCount = 2, .data = (uint8_t const *)"ta" },
		};
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data());
		SnortFs::replayRecorder_recordInstruction(file, 1, diffs.data()+1);
	}
	SnortFs::replayRecorder_close(file);
	Assert(file.handle == 0);
}

int32_t main() {
	// replay tests
	replayTest1();
	replayTest2();
	return 0;
}
