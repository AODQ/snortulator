#include <snort-replay/fs.hpp>

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct MemoryRegionDiff {
	uint64_t byteOffset;
	uint64_t byteCount;
	std::vector<uint8_t> data;
};

struct FileInstruction {
	std::vector<std::vector<MemoryRegionDiff>> regionDiffs;
	std::vector<std::vector<SnortFs::MemoryRegionDiff>> regionDiffRaw;
};

struct FileData {
	uint64_t instructionOffset;
	uint64_t regionCount;
	std::vector<FileInstruction> instructions;

	std::string recordingFilepath;
	uint64_t recordingRegionOffset {0};
	uint64_t recordingInstructionIndex {0};
	uint64_t recordingByteCount {0};
};

} // namespace

// -----------------------------------------------------------------------------
// -- snort fs impl ------------------------------------------------------------
// -----------------------------------------------------------------------------

SnortFs::ReplayFile SnortFs::replayOpen(char const * const filepath) {
	FILE * filePtr = fopen(filepath, "rb");
	if (filePtr == nullptr) {
		printf("failed to open replay file %s\n", filepath);
		return SnortFs::ReplayFile { 0 };
	}
	// -- read magic number
	{
		std::array<char, 8> magic;
		fread(magic.data(), 1, 8, filePtr);
		if (memcmp(magic.data(), "SNORTRPL", 8) != 0) {
			printf("failed to read magic number of file %s\n", filepath);
			printf("'%c' '%c' '%c' '%c' '%c' '%c' '%c' '%c'\n",
				magic[0], magic[1], magic[2], magic[3],
				magic[4], magic[5], magic[6], magic[7]
			);
			fflush(filePtr);
			fclose(filePtr);
			return SnortFs::ReplayFile { 0 };
		}
	}

	FileData fileData {};

	// -- read instruction offset, instruction count and region count
	fread(&fileData.instructionOffset, 8, 1, filePtr);
	{
		uint64_t instructionCount;
		uint64_t regionCount;
		fread(&instructionCount, 8, 1, filePtr);
		fread(&regionCount, 8, 1, filePtr);
		fileData.instructions.resize(instructionCount);
		fileData.regionCount = regionCount;
	}

	// -- read per-instruction diffs
	for (size_t instrIt = 0; instrIt < fileData.instructions.size(); ++instrIt) {
		auto & instruction = fileData.instructions[instrIt];
		instruction.regionDiffs.resize(fileData.regionCount);
		instruction.regionDiffRaw.resize(fileData.regionCount);
		// read per-memory region diffs
		for (size_t regionIt = 0; regionIt < fileData.regionCount; ++regionIt) {
			uint64_t diffCount;
			fread(&diffCount, 8, 1, filePtr);
			instruction.regionDiffs[regionIt].resize(diffCount);
			instruction.regionDiffRaw[regionIt].resize(diffCount);
			for (size_t diffIt = 0; diffIt < diffCount; ++diffIt) {
				uint64_t byteOffset;
				uint64_t byteCount;
				fread(&byteOffset, 8, 1, filePtr);
				fread(&byteCount, 8, 1, filePtr);
				std::vector<uint8_t> data(byteCount);
				fread(data.data(), 1, byteCount, filePtr);
				instruction.regionDiffs[regionIt][diffIt] = {
					.byteOffset = byteOffset,
					.byteCount = byteCount,
					.data = std::move(data),
				};
				instruction.regionDiffRaw[regionIt][diffIt] = {
					.byteOffset = byteOffset,
					.byteCount = byteCount,
					.data = instruction.regionDiffs[regionIt][diffIt].data.data(),
				};
			}
		}
	}

	// -- read magic number to verify instructions were read correctly
	{
		std::array<char, 8> magic;
		fread(magic.data(), 1, 8, filePtr);
		if (memcmp(magic.data(), "SNORTRPL", 8) != 0) {
			printf("failed to readback magic number %s\n", filepath);
			fclose(filePtr);
			return SnortFs::ReplayFile { 0 };
		}
	}

	fclose(filePtr);
	return SnortFs::ReplayFile {
		(uint64_t)(uintptr_t)(new FileData(std::move(fileData)))
	};
}

// --

void SnortFs::replayClose(ReplayFile & file) {
	if (file.handle == 0) { return; }
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	delete fileDataPtr;
	file.handle = 0;
}

// --

uint64_t SnortFs::replayInstructionOffset(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->instructionOffset;
}

// --

uint64_t SnortFs::replayInstructionCount(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->instructions.size();
}

// --

uint64_t SnortFs::replayRegionCount(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->regionCount;
}

// --

size_t SnortFs::replayInstructionDiffCount(
	ReplayFile const file,
	size_t const instructionIndex,
	size_t const regionIndex
) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return (
		fileDataPtr
		->instructions[instructionIndex].regionDiffs[regionIndex].size()
	);
}

// --

SnortFs::MemoryRegionDiff * SnortFs::replayInstructionDiff(
	ReplayFile const file,
	size_t const instructionIndex,
	size_t const regionIndex
) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	auto & diffs = (
		fileDataPtr
		->instructions[instructionIndex].regionDiffRaw[regionIndex]
	);
	return diffs.data();
}

// -----------------------------------------------------------------------------
// -- snort fs recording impl --------------------------------------------------
// -----------------------------------------------------------------------------

SnortFs::ReplayFileRecorder SnortFs::replayRecordOpen(
	char const * const filepath,
	uint64_t const instructionOffset,
	uint64_t const regionCount
) {
	FileData const fileData {
		.instructionOffset = instructionOffset,
		.regionCount = regionCount,
		.instructions = {},
		.recordingFilepath = filepath,
	};
	printf("starting recording to file '%s' with instruction offset %zu and region count %zu\n",
		fileData.recordingFilepath.c_str(),
		(size_t)fileData.instructionOffset,
		(size_t)fileData.regionCount
	);
	return SnortFs::ReplayFileRecorder {
		(uint64_t)(uintptr_t)(new FileData(std::move(fileData)))
	};
}

// --

void SnortFs::replayRecordClose(ReplayFileRecorder & recorder) {
	if (recorder.handle == 0u) { return; }
	FileData & fileData = *(FileData *)(uintptr_t)(recorder.handle);
	if (fileData.recordingRegionOffset != fileData.regionCount) {
		printf(
			"warning: recording ended with incomplete instruction, "
			"recorded %zu regions out of %zu for instruction %zu\n",
			(size_t)fileData.recordingRegionOffset,
			(size_t)fileData.regionCount,
			(size_t)fileData.recordingInstructionIndex
		);
	}

	printf(
		"closing recording to file '%s', recorded %zu instructions and"
		" %zu total KiB\n",
		fileData.recordingFilepath.c_str(),
		fileData.instructions.size(),
		(size_t)(fileData.recordingByteCount / 1024ull)
	);

	FILE * filePtr = fopen(fileData.recordingFilepath.c_str(), "wb");

	if (filePtr == nullptr) {
		printf(
			"error: failed to open file for writing replay recording at '%s'\n",
			fileData.recordingFilepath.c_str()
		);
		delete &fileData;
		recorder.handle = 0;
		fflush(filePtr);
		fclose(filePtr);
		return;
	}

	// -- write magic number
	{
		std::array<char, 8> magic = { 'S', 'N', 'O', 'R', 'T', 'R', 'P', 'L' };
		fwrite(magic.data(), 1, 8, filePtr);
	}

	// -- write instruction offset, instruction count and region count
	fwrite(&fileData.instructionOffset, 8, 1, filePtr);
	{
		uint64_t instructionCount = fileData.instructions.size();
		uint64_t regionCount = fileData.regionCount;
		fwrite(&instructionCount, 8, 1, filePtr);
		fwrite(&regionCount, 8, 1, filePtr);
	}

	// -- write per-instruction diffs
	for (size_t instrIt = 0; instrIt < fileData.instructions.size(); ++instrIt) {
		auto const & instruction = fileData.instructions[instrIt];
		// write per-memory region diffs
		for (size_t regionIt = 0; regionIt < fileData.regionCount; ++regionIt) {
			uint64_t diffCount = instruction.regionDiffs[regionIt].size();
			fwrite(&diffCount, 8, 1, filePtr);
			for (size_t diffIt = 0; diffIt < diffCount; ++diffIt) {
				auto const & diff = instruction.regionDiffs[regionIt][diffIt];
				fwrite(&diff.byteOffset, 8, 1, filePtr);
				fwrite(&diff.byteCount, 8, 1, filePtr);
				fwrite(diff.data.data(), 1, diff.data.size(), filePtr);
			}
		}
	}

	// -- write magic number to verify instructions were read correctly
	{
		std::array<char, 8> magic = { 'S', 'N', 'O', 'R', 'T', 'R', 'P', 'L' };
		fwrite(magic.data(), 1, 8, filePtr);
	}

	delete &fileData;
	fflush(filePtr);
	fclose(filePtr);
	recorder.handle = 0;
}

// --

void SnortFs::replayRecord(
	ReplayFileRecorder & recorder,
	size_t const diffCount,
	MemoryRegionDiffRecord const * diffs
) {
	if (recorder.handle == 0) {
		printf(
			"err: recording replay diff with invalid file recorder\n"
		);
		return;
	}
	FileData & fileData = *(FileData *)(uintptr_t)(recorder.handle);
	// -- check if need to start a new instruction
	if (fileData.recordingRegionOffset >= fileData.regionCount) {
		fileData.recordingRegionOffset = 0;
		fileData.recordingInstructionIndex += 1;
		fileData.instructions.emplace_back();
		fileData.instructions.back().regionDiffs.resize(fileData.regionCount);
	}
	else if (fileData.instructions.size() == 0) {
		// no instruction started
		fileData.instructions.emplace_back();
		fileData.instructions.back().regionDiffs.resize(fileData.regionCount);
	}

	// -- track new byte count
	for (size_t it = 0; it < diffCount; ++ it) {
		fileData.recordingByteCount += diffs[it].byteCount;
	}

	// -- store the diffs for the current instruction and region
	auto & instruction = (
		fileData.instructions[fileData.recordingInstructionIndex]
	);
	instruction.regionDiffs[fileData.recordingRegionOffset].resize(diffCount);
	for (size_t it = 0; it < diffCount; ++ it) {
		instruction.regionDiffs[fileData.recordingRegionOffset][it] = {
			.byteOffset = diffs[it].byteOffset,
			.byteCount = diffs[it].byteCount,
			.data = std::vector<uint8_t>(
				diffs[it].data,
				diffs[it].data + diffs[it].byteCount
			),
		};
	}

	fileData.recordingRegionOffset += 1;

	// for now limit to 64MiB diffs, anything more is probably 
	if (fileData.recordingRegionOffset == fileData.regionCount) {
		if (fileData.recordingByteCount > 64ull * 1024ull * 1024ull) {
			printf(
				"error: recording instruction %zu with large byte count %zu,\n"
				"prematurely closing\n",
				(size_t)fileData.recordingInstructionIndex,
				(size_t)fileData.recordingByteCount
			);
			SnortFs::replayRecordClose(recorder);
		}
	}
}
