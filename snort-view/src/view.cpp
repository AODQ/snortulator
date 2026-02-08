#include <snort-replay/fs.hpp>

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
		SnortFs::replayClose(sOpenReplay.file);
	}
	SnortFs::ReplayFile file = SnortFs::replayOpen(filepath.c_str());
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
		(size_t)SnortFs::replayInstructionOffset(replay.file)
	);
	ImGui::Text(
		"instruction count: %zu",
		(size_t)SnortFs::replayInstructionCount(replay.file)
	);
	ImGui::Text(
		"region count: %zu",
		(size_t)SnortFs::replayRegionCount(replay.file)
	);
	ImGui::End();

	// -- display memory regions
	ImGui::Begin("replay instruction diffs");
	if (ImGui::Button("prev instruction")) {
		if (sReplayInstructionIndex > 0) {
			-- sReplayInstructionIndex;
		}
	}
	if (ImGui::Button("next instruction")) {
		if (sReplayInstructionIndex + 1 < SnortFs::replayInstructionCount(replay.file)) {
			++ sReplayInstructionIndex;
		}
	}
	ImGui::Text("current instruction index: %zu", sReplayInstructionIndex);
	for (
		size_t regionIt = 0;
		regionIt < SnortFs::replayRegionCount(replay.file);
		++ regionIt
	) {
		size_t diffCount = SnortFs::replayInstructionDiffCount(
			replay.file,
			sReplayInstructionIndex,
			regionIt
		);
		ImGui::Text(" -- region %zu --", regionIt);
		ImGui::Text("diff count: %zu", diffCount);
		auto const & diffs = (
			SnortFs::replayInstructionDiff(
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
}

// -----------------------------------------------------------------------------

int32_t main() {
	SetTraceLogLevel(LOG_ERROR);
	InitWindow(1200, 600, "snort replay viewer");
	SetTargetFPS(60);
	rlImGuiSetup(true);
	ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_DockingEnable;
	ImGui::GetIO().IniFilename = "imgui-view.ini";

	while (WindowShouldClose() == false) {
		BeginDrawing();
		ClearBackground(DARKGRAY);
		rlImGuiBegin();

		ImGui::DockSpaceOverViewport();

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

		rlImGuiEnd();
		EndDrawing();
	}


	// shutdown
	rlImGuiShutdown();
	CloseWindow();
	return 0u;
}
