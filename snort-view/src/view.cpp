#include <snort-replay/fs.hpp>

#include <snort-replay/validation.hpp>

#include <snort/snort-ui.h>

#include <ImGuiFileDialog.h>
#include <imgui.h>
#include <rlImGui.h>

// -----------------------------------------------------------------------------

struct ReplayFile {
	std::string filepath;
	SnortFs::ReplayFile file;
};

static ReplayFile sOpenReplay { .file = {.handle = 0} };
static ReplayFile sOpenReplayCmp { .file = {.handle = 0} };
static bool sIsComparisonFlip { false };
static size_t sReplayInstructionIndex { 0 };


// -----------------------------------------------------------------------------

void openReplayFile(ReplayFile & rf, std::string const & filepath) {
	if (rf.file.handle != 0) {
		SnortFs::replay_close(rf.file);
	}
	SnortFs::ReplayFile file = SnortFs::replay_open(filepath.c_str());
	if (file.handle == 0) {
		printf("failed to open replay file %s\n", filepath.c_str());
		return;
	}
	rf = {
		.filepath = filepath,
		.file = file,
	};
};

// -----------------------------------------------------------------------------

bool verifyReplayFilesCompatible(
	ReplayFile const & replay,
	ReplayFile const & replayCmp
) {
	if (replay.file.handle == 0 || replayCmp.file.handle == 0) {
		return false;
	}
	auto const rfInfo = SnortFs::replay_regionInfo(replay.file);
	auto const rcInfo = SnortFs::replay_regionInfo(replayCmp.file);
	auto const rfInstrCount = SnortFs::replay_instructionCount(replay.file);
	auto const rcInstrCount = SnortFs::replay_instructionCount(replayCmp.file);
	auto const rfInstrOffset = SnortFs::replay_instructionOffset(replay.file);
	auto const rcInstrOffset = SnortFs::replay_instructionOffset(replayCmp.file);
	auto const rfRegionCount = SnortFs::replay_regionCount(replay.file);
	auto const rcRegionCount = SnortFs::replay_regionCount(replayCmp.file);
	if (rfInstrOffset != rcInstrOffset) {
		printf("instruction offset mismatch between replay files\n");
		return false;
	}
	if (rfInstrCount != rcInstrCount) {
		printf("instruction count mismatch between replay files\n");
		return false;
	}
	if (rfRegionCount != rcRegionCount) {
		printf("region count mismatch between replay files\n");
		return false;
	}
	for (size_t rc = 0; rc < rfRegionCount; ++ rc) {
		if (
			   rfInfo[rc].dataType != rcInfo[rc].dataType
			|| rfInfo[rc].elementCount != rcInfo[rc].elementCount
			|| (
				rfInfo[rc].elementDisplayRowStride
				!= rcInfo[rc].elementDisplayRowStride
			)
			|| strcmp(rfInfo[rc].label, rcInfo[rc].label) != 0
		) {
			printf("region info mismatch between replay files\n");
			return false;
		}
	}
	return true;
}

std::vector<std::vector<uint8_t>>
regionBuildUpToInstructionIndex(
	ReplayFile const & replay,
	size_t instructionIndex
)
{
	std::vector<std::vector<uint8_t>> regionData(
		SnortFs::replay_regionCount(replay.file)
	);
	for (size_t regIt = 0; regIt < regionData.size(); ++regIt) {
		auto const & regionInfo = SnortFs::replay_regionInfo(replay.file)[regIt];
		regionData[regIt].resize(
			regionInfo.elementCount * snort_dtByteCount(regionInfo.dataType)
		);
		// for each instruction apply the diffs to the current region
		for (size_t instrIt = 0; instrIt <= sReplayInstructionIndex; ++instrIt) {
			auto const diffCount = (
				SnortFs::replay_instructionDiffCount(replay.file, instrIt, regIt)
			);
			auto const & diffs = (
				SnortFs::replay_instructionDiff(replay.file, instrIt, regIt)
			);
			for (size_t diffIt = 0; diffIt < diffCount; ++diffIt) {
				auto const & diff = diffs[diffIt];
				for (size_t byteIt = 0; byteIt < diff.byteCount; ++byteIt) {
					regionData[regIt][diff.byteOffset + byteIt] = diff.data[byteIt];
				}
			}
		}
	}
	return regionData;
}

// -----------------------------------------------------------------------------

void displayReplayFile(ReplayFile const & replay, ReplayFile & replayCmp) {
	// -- display replay file info
	ImGui::Begin("replay file info");
	ImGui::Text(
		"instruction offset: %zu",
		(size_t)SnortFs::replay_instructionOffset(replay.file)
	);
	ImGui::Text(
		"instruction count: %zu",
		(size_t)SnortFs::replay_instructionCount(replay.file)
	);
	ImGui::Text(
		"region count: %zu",
		(size_t)SnortFs::replay_regionCount(replay.file)
	);
	ImGui::End();

	// -- display memory regions
	ImGui::Begin("replay instruction diffs");
	ImGui::Text("Instruction index");
	ImGui::SliderInt(
		"##instructionIndexSlider",
		(int *)&sReplayInstructionIndex,
		0,
		(int)(SnortFs::replay_instructionCount(replay.file) - 1)
	);
	if (ImGui::Button("<") && sReplayInstructionIndex > 0) {
		-- sReplayInstructionIndex;
	}
	ImGui::SameLine();
	size_t const instrCount = SnortFs::replay_instructionCount(replay.file);
	if (ImGui::Button(">") && sReplayInstructionIndex+1 < instrCount) {
		++ sReplayInstructionIndex;
	}

	// validate all memory
	static size_t invalidFrame = ~0u;
	// static i32 invalidFrameDuration = 0;
	if (replayCmp.file.handle != 0 && ImGui::Button("validate all memory")) {
		invalidFrame = SnortFs::validateMemory(replay.file, replayCmp.file);
		// invalidFrameDuration = 120;
		ImGui::OpenPopup("validation result");
	}
	if (ImGui::BeginPopup("validation result")) {
		ImGui::Text("validation result:");
		if (invalidFrame == ~0u) {
			ImGui::Text("all frames valid");
		}
		else {
			ImGui::Text("first invalid frame: %zu", invalidFrame);
			if (ImGui::Button("go to invalid frame")) {
				sReplayInstructionIndex = invalidFrame;
				ImGui::CloseCurrentPopup();
			}
		}
		ImGui::EndPopup();
	}

	// -- display this replay's filename
	ImGui::Text("primary replay file:");
	ImGui::TextWrapped("%s", replay.filepath.c_str());
	// -- display comparison replay filename if open
	if (replayCmp.file.handle != 0) {
		ImGui::Text("comparison replay file:");
		ImGui::TextWrapped("%s", replayCmp.filepath.c_str());
	}
	ImGui::Text("index: %zu", sReplayInstructionIndex);
	ImGui::Checkbox("view secondary data", &sIsComparisonFlip);
	for (
		size_t regionIt = 0;
		regionIt < SnortFs::replay_regionCount(replay.file);
		++ regionIt
	) {
		size_t diffCount = SnortFs::replay_instructionDiffCount(
			replay.file,
			sReplayInstructionIndex,
			regionIt
		);
		ImGui::Text(" -- region %zu --", regionIt);
		ImGui::Text("diff count: %zu", diffCount);
		auto const & diffs = (
			SnortFs::replay_instructionDiff(
				replay.file,
				sReplayInstructionIndex,
				regionIt
			)
		);
		for (size_t diffIt = 0; diffIt < diffCount; ++ diffIt) {
			ImGui::Text(
				"diff %zu: offset %zu, count %zu",
				diffIt,
				(size_t)diffs[diffIt].byteOffset,
				(size_t)diffs[diffIt].byteCount
			);
		}
	}
	ImGui::End();

	// TODO this can be optimized
	// build up the current memory region data by applying diffs
	std::vector<std::vector<uint8_t>> const regionData = (
		regionBuildUpToInstructionIndex(replay, sReplayInstructionIndex)
	);
	std::vector<std::vector<uint8_t>> const regionDataCmp = (
		replayCmp.file.handle != 0
		? regionBuildUpToInstructionIndex(replayCmp, sReplayInstructionIndex)
		: std::vector<std::vector<uint8_t>>{}
	);

	// transform into array of pointers
	std::vector<u8 const *> regionDataPtr(regionData.size());
	for (size_t it = 0; it < regionData.size(); ++it) {
		regionDataPtr[it] = regionData[it].data();
	}

	std::vector<u8 const *> regionDataCmpPtr(regionDataCmp.size());
	for (size_t it = 0; it < regionDataCmp.size(); ++it) {
		regionDataCmpPtr[it] = regionDataCmp[it].data();
	}

	if (sIsComparisonFlip && replayCmp.file.handle != 0) {
		std::swap(regionDataPtr, regionDataCmpPtr);
	}

	snort_displayMemory(
		/*commonInterface=*/ SnortFs::replay_commonInterface(replay.file),
		/*regions=*/ SnortFs::replay_regionCount(replay.file),
		/*regionInfo=*/ SnortFs::replay_regionInfo(replay.file),
		/*regionData=*/ regionDataPtr.data(),
		/*optRegionDataCmp=*/ (
			replayCmp.file.handle != 0 ? regionDataCmpPtr.data() : nullptr
		)
	);
}

// -----------------------------------------------------------------------------

int32_t main(int32_t const argc, char const * const argv[]) {
	snort_displayInitialize();
	ImGui::GetIO().IniFilename = "imgui-view.ini";

	if (argc > 1) {
		openReplayFile(sOpenReplay, argv[1]);
	}
	if (argc > 2) {
		openReplayFile(sOpenReplayCmp, argv[2]);
		if (!verifyReplayFilesCompatible(sOpenReplay, sOpenReplayCmp)) {
			printf("replay files are not compatible for comparison\n");
			SnortFs::replay_close(sOpenReplayCmp.file);
			sOpenReplayCmp.file.handle = 0;
		}
	}

	while (WindowShouldClose() == false) {
		snort_displayFrameBegin();

		ImGui::Begin("stats");
		ImGui::Text("FPS: %d", GetFPS());
		ImGui::End();

		// -- file dialog
		ImGui::Begin("file");
		if (ImGui::Button("open replay file")) {
			ImGuiFileDialog::Instance()->OpenDialog(
				"ReplayFileDlgKey",
				"Choose Replay File",
				".rpl\0"
			);
		}
		if (sOpenReplay.file.handle != 0) {
			if (ImGui::Button("open comparison replay file")) {
				ImGuiFileDialog::Instance()->OpenDialog(
					"ReplayCmpFileDlgKey",
					"Choose Comparison Replay File",
					".rpl\0"
				);
			}
		}
		ImGui::End();

		// -- display file dialog if open
		if (ImGuiFileDialog::Instance()->Display("ReplayFileDlgKey")) {
			// action if OK
			if (ImGuiFileDialog::Instance()->IsOk()) {
				auto const filePathName = (
					ImGuiFileDialog::Instance()->GetFilePathName()
				);
				openReplayFile(sOpenReplay, filePathName);
				sReplayInstructionIndex = 0;
				sIsComparisonFlip = false;
			}
			// close
			ImGuiFileDialog::Instance()->Close();
		}

		if (ImGuiFileDialog::Instance()->Display("ReplayCmpFileDlgKey")) {
			// action if OK
			if (ImGuiFileDialog::Instance()->IsOk()) {
				auto const filePathName = (
					ImGuiFileDialog::Instance()->GetFilePathName()
				);
				openReplayFile(sOpenReplayCmp, filePathName);
				if (!verifyReplayFilesCompatible(sOpenReplay, sOpenReplayCmp)) {
					printf("replay files are not compatible for comparison\n");
					SnortFs::replay_close(sOpenReplayCmp.file);
					sOpenReplayCmp.file.handle = 0;
				}
			}
			// close
			ImGuiFileDialog::Instance()->Close();
		}

		if (sOpenReplay.file.handle != 0) {
			displayReplayFile(sOpenReplay, sOpenReplayCmp);
		}

		snort_displayFrameEnd();
	}

	snort_displayDestroy();
	return 0u;
}
