#include <snort/snort.h>

// -----------------------------------------------------------------------------
// -- snort harness frame processing -------------------------------------------
// -----------------------------------------------------------------------------

struct SnortDeviceCreateInfo {
	char const * name;
	SnortMemoryRegionCreateInfo const * memoryRegions;
	size_t memoryRegionCount;
};
struct SnortDevice { u64 handle; };
SnortDevice snort_deviceCreate(SnortDeviceCreateInfo const * ci);
void snort_deviceDestroy(SnortDevice * device);

bool snort_shouldQuit(SnortDevice const device);
// returns true if the frame should be processed. If this is false, then do
//   not process the frame.
bool snort_startFrame(SnortDevice const device);


// memory region must be in the same order as it appeared in device creation.
struct SnortMemoryRegion {
	u8 const * data;
};
void snort_endFrame(
	SnortDevice const device,
	SnortMemoryRegion const * memoryRegions
);

// -----------------------------------------------------------------------------
// -- snort harness deterministic synchronization ------------------------------
// -----------------------------------------------------------------------------

u64 snort_rngU64(SnortDevice const device);
f32 snort_rngF32(SnortDevice const device);

// -----------------------------------------------------------------------------
// -- snort common harness interfaces ------------------------------------------
// -----------------------------------------------------------------------------

// common emulator interface
enum SnortCommonInterface {
	kSnortCommonInterface_chip8,
};
SnortDevice snort_deviceCreateFromCommon(SnortCommonInterface const type);
