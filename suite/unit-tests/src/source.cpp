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
			.memoryRegionCount = memoryRegions.size(),
			.memoryRegions = memoryRegions.data(),
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

		bool const shouldRunFrame = (
			snort_startFrame(
				device,
				(SnortMemoryRegion const []) {
					{ registers.data() },
					{ (u8 const *)memory.data() },
					{ display.data() },
				}
			)
		);

		// -- test configs
		static bool colorScheme = false;
		ImGui::Begin("test configs");
		ImGui::Checkbox("color scheme", &colorScheme);
		ImGui::End();

		// -- update registers
		if (shouldRunFrame) {
			if (colorScheme) {
				registers[0] += 7;
				registers[1] += 4;
				registers[2] += 4;
			} else {
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
				if (!colorScheme) {
					display[index + 0] = ((y+fc) % 256);
					display[index + 1] = ((x+fc) % 256);
					display[index + 2] = ((x + y) % 256);
					display[index + 3] = 255;
				}
				else {
					display[index + 0] = ((x+fc) % 256);
					display[index + 1] = ((y+fc) % 256);
					display[index + 2] = ((x + y) % 256);
					if (x < 32 && y < 32) {
						display[index + 3] = 255;
					} else {
						display[index + 3] = 255 - ((x+y) % 256);
					}
					if (x > 32 && y > 16) {
						display[index + 1] = (y%3)*100;
					}
					display[index + 2] = (x%3)*50;

					display[index + 3] = 255;
				}
			};

			// -- update random memory
			if (colorScheme) {
				memory[0] = snort_rngU64(device);
				memory[1] = snort_rngU64(device);
				memory[2] = snort_rngU64(device);
				memory[3] = snort_rngU64(device);
			} else {
				memory[3] = snort_rngU64(device);
				memory[2] = snort_rngU64(device);
				memory[2] = snort_rngU64(device);
				memory[0] = snort_rngU64(device);
			}
		}

		snort_endFrame(device);
	}

	snort_deviceDestroy(&device);
	return 0;
}
