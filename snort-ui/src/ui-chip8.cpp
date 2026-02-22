#include <snort/snort-ui.h>

namespace gui {
	void displayDeviceChip8(
		size_t regions,
		SnortMemoryRegionCreateInfo const * regionInfo,
		u8 const * const * regionData,
		u8 const * const * optRegionDataCmp
	);
}

// --

static void displayDeviceChip8Memory(
	size_t regions,
	SnortMemoryRegionCreateInfo const * regionInfo,
	u8 const * const * regionData
) {
	// -- fetch memory
	// these need to map to device-common.cpp
	auto & memory = regionData[0];
	auto & programCounter = regionData[4];

	// -- fetch opcode
	u16 opcode = (
		  (u16)(memory[programCounter[0]] << 8)
		| (u16)(memory[programCounter[0] + 1u])
	);

	// -- decode and execute
	u8 const msb0 = (opcode & 0xF000u) >> 12u;
	u8 const msb1 = (opcode & 0x0F00u) >> 8u;
	u8 const msb2 = (opcode & 0x00F0u) >> 4u;
	u8 const msb3 = (opcode & 0x000Fu);
	ImGui::Text("opcode: 0x%04X", opcode);
	switch (msb0) {
		case 0x0:
			switch (opcode) {
				case 0x00E0:
					ImGui::Text("clear display");
					break;
				case 0x00EE:
					ImGui::Text("subroutine return");
					break;
				default:
					ImGui::Text("call RCA 1802 program at address NNN");
					break;
			}
		break;
		case 0x1:
			ImGui::Text("jump to address NNN");
		break;
		case 0x2:
			ImGui::Text("call subroutine at NNN");
		break;
		case 0x3:
			ImGui::Text(
				"skip next instruction if V%X == 0x%02X",
				msb1, (u8)(opcode & 0x00FFu)
			);
		break;
		case 0x4:
			ImGui::Text(
				"skip next instruction if V%X != 0x%02X",
				msb1, (u8)(opcode & 0x00FFu)
			);
		break;
		case 0x5:
			if (msb3 == 0x0u) {
				ImGui::Text(
					"skip next instruction if V%X == V%X",
					msb1, msb2
				);
				break;
			}
			ImGui::Text("unknown opcode");
		break;
		case 0x6:
			ImGui::Text(
				"set V%X = 0x%02X",
				msb1, (u8)(opcode & 0x00FFu)
			);
		break;
		case 0x7:
			ImGui::Text(
				"set V%X = V%X + 0x%02X",
				msb1, msb1, (u8)(opcode & 0x00FFu)
			);
		break;
		case 0x8: {
			switch (msb3) {
				case 0x0: ImGui::Text("set V%X = V%X", msb1, msb2); break;
				case 0x1:
					ImGui::Text("set V%X = V%X OR V%X", msb1, msb1, msb2);
				break;
				case 0x2:
					ImGui::Text("set V%X = V%X AND V%X", msb1, msb1, msb2);
				break;
				case 0x3:
					ImGui::Text("set V%X = V%X XOR V%X", msb1, msb1, msb2);
				break;
				case 0x4:
					ImGui::Text("set V%X = V%X + V%X, set VF = carry", msb1, msb1, msb2);
				break;
				case 0x5:
					ImGui::Text("set V%X = V%X - V%X, set VF = NOT borrow", msb1, msb1, msb2);
				break;
				case 0x6:
					ImGui::Text(
						"set V%X = V%X >> 1, set VF = LSB of V%X", msb1, msb1, msb1
					);
				case 0x7:
					ImGui::Text(
						"set V%X = V%X - V%X, set VF = NOT borrow",
						msb1, msb2, msb1
					);
				case 0xE:
					ImGui::Text(
						"set V%X = V%X << 1, set VF = MSB of V%X", msb1, msb1, msb1
					);
				default: ImGui::Text("unknown opcode"); break;
			}
		} break;
		case 0x9:
			if (msb3 == 0x0u) {
				ImGui::Text(
					"skip next instruction if V%X != V%X",
					msb1, msb2
				);
				break;
			}
			ImGui::Text("unknown opcode");
		break;
		case 0xA: ImGui::Text("set I = NNN"); break;
		case 0xB: ImGui::Text("jump to address NNN + V0"); break;
		case 0xC:
			ImGui::Text(
				"set V%X = random byte AND 0x%02X",
				msb1, (u8)(opcode & 0x00FFu)
			);
		break;
		case 0xD:
			ImGui::Text(
				"draw sprite at (V%X, V%X) with width 8 and height N,"
				" set VF = collision",
				msb1, msb2
			);
		break;
		case 0xE:
			switch (opcode & 0x00FFu) {
				case 0x009E:
					ImGui::Text(
						"skip next instruction if key with value V%X is pressed",
						msb1
					);
				break;
				case 0x00A1:
					ImGui::Text(
						"skip next instruction if key with value V%X is not pressed",
						msb1
					);
				break;
				default: ImGui::Text("unknown opcode"); break;
			}
		break;
		case 0xF:
			if (msb2 == 0x0u && msb3 == 0x7u) { // 07
				ImGui::Text("set V%X = delay timer value", msb1);
			}
			else if (msb2 == 0x1u && msb3 == 0x5u) { // 15
				ImGui::Text("set delay timer = V%X", msb1);
			}
			else if (msb2 == 0x1u && msb3 == 0xEu) { // 1E
				ImGui::Text("set I = I + V%X", msb1);
			}
			else if (msb2 == 0x2u && msb3 == 0x9u) { // 29
				ImGui::Text(
					"set I = location of sprite for character in V%X",
					msb1
				);
			}
			else if (msb2 == 0x3u && msb3 == 0x3u) { // 33
				ImGui::Text(
					"store BCD of V%X in memory locations I, I+1, and I+2",
					msb1
				);
			}
			else if (msb2 == 0x5u && msb3 == 0x5u) { // 55
				ImGui::Text(
					"store registers V0 through V%X in memory starting at I",
					msb1
				);
			}
			else if (msb2 == 0x6u && msb3 == 0x5u) { // 65
				ImGui::Text(
					"read registers V0 through V%X from memory starting at I",
					msb1
				);
			}
			else {
				ImGui::Text("unknown opcode");
			}
		break;
	}
}

// --

void gui::displayDeviceChip8(
	size_t regions,
	SnortMemoryRegionCreateInfo const * regionInfo,
	u8 const * const * regionData,
	u8 const * const * optRegionDataCmp
) {
	ImGui::Begin("instruction info");

	ImGui::Text("-- primary replay instruction decode --");
	displayDeviceChip8Memory(regions, regionInfo, regionData);
	if (optRegionDataCmp) {
		ImGui::Text("-- secondary replay instruction decode --");
		displayDeviceChip8Memory(regions, regionInfo, optRegionDataCmp);
	}

	ImGui::End();
}
