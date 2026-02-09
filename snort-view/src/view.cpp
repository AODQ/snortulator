#include <snort-replay/fs.hpp>

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
static size_t sReplayInstructionIndex { 0 };

void openReplayFile(std::string const & filepath) {
	if (sOpenReplay.file.handle != 0) {
		SnortFs::replay_close(sOpenReplay.file);
	}
	SnortFs::ReplayFile file = SnortFs::replay_open(filepath.c_str());
	if (file.handle == 0) {
		printf("failed to open replay file %s\n", filepath.c_str());
		return;
	}
	sOpenReplay = {
		.filepath = filepath,
		.file = file,
	};
	sReplayInstructionIndex = 0;
};

// -----------------------------------------------------------------------------

void displayReplayFile(ReplayFile const & replay) {
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
	ImGui::SliderInt(
		"Instruction index",
		(int *)&sReplayInstructionIndex,
		0,
		(int)(SnortFs::replay_instructionCount(replay.file) - 1)
	);
	ImGui::Text("current instruction index: %zu", sReplayInstructionIndex);
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
				diffs[diffIt].byteOffset,
				diffs[diffIt].byteCount
			);
		}
	}
	ImGui::End();

	// TODO this can be optimized
	// build up the current memory region data by applying diffs
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

	// transform into array of pointers
	std::vector<u8 const *> regionDataPtr(regionData.size());
	for (size_t it = 0; it < regionData.size(); ++it) {
		regionDataPtr[it] = regionData[it].data();
	}

	snort_displayMemory(
		/*regions=*/ SnortFs::replay_regionCount(replay.file),
		/*regionInfo=*/ SnortFs::replay_regionInfo(replay.file),
		/*regionData=*/ regionDataPtr.data()
	);
}

// -----------------------------------------------------------------------------

int32_t main() {
	snort_displayInitialize();
	ImGui::GetIO().IniFilename = "imgui-view.ini";

	while (WindowShouldClose() == false) {
		snort_displayFrameBegin();

		ImGui::Begin("stats");
		ImGui::Text("FPS: %d", GetFPS());
		ImGui::End();

		// -- file dialog
		ImGui::Begin("file");
		if (ImGui::Button("open replay file")) {
			ImGuiFileDialog::Instance()->OpenDialog(
				"ChooseFileDlgKey",
				"Choose Replay File",
				".rpl\0"
			);
		}
		ImGui::End();

		// -- display file dialog if open
		if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey")) {
			// action if OK
			if (ImGuiFileDialog::Instance()->IsOk()) {
				auto const filePathName = (
					ImGuiFileDialog::Instance()->GetFilePathName()
				);
				openReplayFile(filePathName);
			}
			// close
			ImGuiFileDialog::Instance()->Close();
		}

		if (sOpenReplay.file.handle != 0) {
			displayReplayFile(sOpenReplay);
		}

		snort_displayFrameEnd();
	}

	snort_displayDestroy();
	return 0u;
}
