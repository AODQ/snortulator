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
	SnortCommonInterface commonInterface;
	uint64_t instructionOffset;
	std::vector<SnortMemoryRegionCreateInfo> regionCreateInfo;
	std::vector<std::string> regionLabels;
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

SnortFs::ReplayFile SnortFs::replay_open(char const * const filepath) {
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

	// -- read common interface
	{
		uint64_t commonInterface;
		fread(&commonInterface, 8, 1, filePtr);
		fileData.commonInterface = (SnortCommonInterface)commonInterface;
	}

	// -- read instruction offset, instruction count and region count
	fread(&fileData.instructionOffset, 8, 1, filePtr);
	{
		uint64_t instructionCount;
		uint64_t regionCount;
		fread(&instructionCount, 8, 1, filePtr);
		fread(&regionCount, 8, 1, filePtr);
		fileData.instructions.resize(instructionCount);
		fileData.regionCreateInfo.resize(regionCount);
		fileData.regionLabels.resize(regionCount);
	}

	// read per-memory region create info
	for (size_t regIt = 0; regIt < fileData.regionCreateInfo.size(); ++regIt) {
		auto & regionInfo = fileData.regionCreateInfo[regIt];
		fread(&regionInfo.dataType, 8, 1, filePtr);
		fread(&regionInfo.elementCount, 8, 1, filePtr);
		fread(&regionInfo.elementDisplayRowStride, 8, 1, filePtr);
		char labelBuffer[256];
		memset(labelBuffer, 0, 256);
		for (size_t it = 0; it < 256; ++it) {
			char c;
			fread(&c, 1, 1, filePtr);
			if (c == '\0') { break; }
			labelBuffer[it] = c;
		}
		fileData.regionLabels[regIt] = std::string(labelBuffer);
		regionInfo.label = fileData.regionLabels[regIt].c_str();
	}

	// -- read per-instruction diffs
	for (size_t instrIt = 0; instrIt < fileData.instructions.size(); ++instrIt) {
		auto & instruction = fileData.instructions[instrIt];
		auto const regionCount = fileData.regionCreateInfo.size();
		instruction.regionDiffs.resize(regionCount);
		instruction.regionDiffRaw.resize(regionCount);
		// read per-memory region diffs
		for (size_t regionIt = 0; regionIt < regionCount; ++regionIt) {
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

void SnortFs::replay_close(ReplayFile & file) {
	if (file.handle == 0) { return; }
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	delete fileDataPtr;
	file.handle = 0;
}

// --

SnortCommonInterface SnortFs::replay_commonInterface(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->commonInterface;
}

// --

uint64_t SnortFs::replay_instructionOffset(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->instructionOffset;
}

// --

uint64_t SnortFs::replay_instructionCount(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->instructions.size();
}

// --

uint64_t SnortFs::replay_regionCount(ReplayFile const file) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->regionCreateInfo.size();
}

// --

SnortMemoryRegionCreateInfo const * SnortFs::replay_regionInfo(
	ReplayFile const file
) {
	FileData * fileDataPtr = (FileData *)(uintptr_t)(file.handle);
	return fileDataPtr->regionCreateInfo.data();
}

// --

size_t SnortFs::replay_instructionDiffCount(
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

SnortFs::MemoryRegionDiff * SnortFs::replay_instructionDiff(
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

SnortFs::ReplayFileRecorder SnortFs::replayRecorder_open(
	char const * const filepath,
	SnortCommonInterface const commonInterface,
	uint64_t const instructionOffset,
	uint64_t const regionCount,
	SnortMemoryRegionCreateInfo const * const regionCreateInfo
) {
	FileData fileData {
		.commonInterface = commonInterface,
		.instructionOffset = instructionOffset,
		.regionCreateInfo = std::vector<SnortMemoryRegionCreateInfo>(regionCount),
		.regionLabels = std::vector<std::string>(regionCount),
		.instructions = {},
		.recordingFilepath = filepath,
	};
	for (size_t it = 0; it < regionCount; ++it) {
		fileData.regionCreateInfo[it] = regionCreateInfo[it];
		fileData.regionLabels[it] = std::string(regionCreateInfo[it].label);
		fileData.regionCreateInfo[it].label = fileData.regionLabels[it].c_str();
	}
	printf("starting recording to file '%s' with instruction offset %zu and region count %zu\n",
		fileData.recordingFilepath.c_str(),
		(size_t)fileData.instructionOffset,
		(size_t)fileData.regionCreateInfo.size()
	);
	return SnortFs::ReplayFileRecorder {
		(uint64_t)(uintptr_t)(new FileData(std::move(fileData)))
	};
}

// --

void SnortFs::replayRecorder_close(ReplayFileRecorder & recorder) {
	if (recorder.handle == 0u) { return; }
	FileData & fileData = *(FileData *)(uintptr_t)(recorder.handle);
	if (fileData.recordingRegionOffset != fileData.regionCreateInfo.size()) {
		printf(
			"warning: recording ended with incomplete instruction, "
			"recorded %zu regions out of %zu for instruction %zu\n",
			(size_t)fileData.recordingRegionOffset,
			(size_t)fileData.regionCreateInfo.size(),
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

	// -- write common interface
	{
		uint64_t commonInterface = (uint64_t)fileData.commonInterface;
		fwrite(&commonInterface, 8, 1, filePtr);
	}

	// -- write instruction offset, instruction count and region count
	fwrite(&fileData.instructionOffset, 8, 1, filePtr);
	{
		uint64_t instructionCount = fileData.instructions.size();
		uint64_t regionCount = fileData.regionCreateInfo.size();
		fwrite(&instructionCount, 8, 1, filePtr);
		fwrite(&regionCount, 8, 1, filePtr);
	}

	// write per-memory region create info
	for (size_t regIt = 0; regIt < fileData.regionCreateInfo.size(); ++regIt) {
		auto const & regionInfo = fileData.regionCreateInfo[regIt];
		fwrite(&regionInfo.dataType, 8, 1, filePtr);
		fwrite(&regionInfo.elementCount, 8, 1, filePtr);
		fwrite(&regionInfo.elementDisplayRowStride, 8, 1, filePtr);
		for (char const c : fileData.regionLabels[regIt]) {
			fwrite(&c, 1, 1, filePtr);
		}
		fwrite("\0", 1, 1, filePtr);
	}

	// -- write per-instruction diffs
	for (size_t instrIt = 0; instrIt < fileData.instructions.size(); ++instrIt) {
		auto const & instruction = fileData.instructions[instrIt];
		// write per-memory region diffs
		for (size_t regIt = 0; regIt < fileData.regionCreateInfo.size(); ++regIt){
			uint64_t diffCount = instruction.regionDiffs[regIt].size();
			fwrite(&diffCount, 8, 1, filePtr);
			for (size_t diffIt = 0; diffIt < diffCount; ++diffIt) {
				auto const & diff = instruction.regionDiffs[regIt][diffIt];
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

void SnortFs::replayRecorder_recordInstruction(
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
	auto const regionCount = fileData.regionCreateInfo.size();
	// -- check if need to start a new instruction
	if (fileData.recordingRegionOffset >= regionCount) {
		fileData.recordingRegionOffset = 0;
		fileData.recordingInstructionIndex += 1;
		fileData.instructions.emplace_back();
		fileData.instructions.back().regionDiffs.resize(regionCount);
	}
	else if (fileData.instructions.size() == 0) {
		// no instruction started
		fileData.instructions.emplace_back();
		fileData.instructions.back().regionDiffs.resize(regionCount);
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
		std::vector<uint8_t> data;
		data.resize(diffs[it].byteCount);
		memcpy(data.data(), diffs[it].data, data.size());
		instruction.regionDiffs[fileData.recordingRegionOffset][it] = {
			.byteOffset = diffs[it].byteOffset,
			.byteCount = diffs[it].byteCount,
			.data = std::move(data),
		};
	}

	fileData.recordingRegionOffset += 1;

	// for now limit to 64MiB diffs, anything more is probably 
	if (fileData.recordingRegionOffset == regionCount) {
		if (fileData.recordingByteCount > 64ull * 1024ull * 1024ull) {
			printf(
				"error: recording instruction %zu with large byte count %zu,\n"
				"prematurely closing\n",
				(size_t)fileData.recordingInstructionIndex,
				(size_t)fileData.recordingByteCount
			);
			SnortFs::replayRecorder_close(recorder);
		}
	}
}
