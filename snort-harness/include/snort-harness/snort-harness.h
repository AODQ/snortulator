#pragma once

#include <snort/snort.h>

// -----------------------------------------------------------------------------
// -- snort handles ------------------------------------------------------------
// -----------------------------------------------------------------------------

struct SnortDevice { u64 handle; };

// -----------------------------------------------------------------------------
// -- snort common harness interfaces ------------------------------------------
// -----------------------------------------------------------------------------

SnortDevice snort_deviceCreateFromCommon(SnortCommonInterface const type);

// -----------------------------------------------------------------------------
// -- snort harness frame processing -------------------------------------------
// -----------------------------------------------------------------------------

SnortDevice snort_deviceCreate(SnortDeviceCreateInfo const * ci);
void snort_deviceDestroy(SnortDevice * device);

// memory region must be in the same order as it appeared in device creation.
struct SnortMemoryRegion {
	u8 const * data;
};

bool snort_shouldQuit(SnortDevice const device);

// returns true if the frame should be processed. If this is false, then do
//   not process the frame.
bool snort_startFrame(
	SnortDevice const device,
	SnortMemoryRegion const * memoryRegions
);

void snort_endFrame(SnortDevice const device);

// -----------------------------------------------------------------------------
// -- snort harness deterministic synchronization ------------------------------
// -----------------------------------------------------------------------------

u64 snort_rngU64(SnortDevice const device);
f32 snort_rngF32(SnortDevice const device);
