#pragma once

#include <snort/snort.h>

// -----------------------------------------------------------------------------
// -- snort handles ------------------------------------------------------------
// -----------------------------------------------------------------------------

struct SnortDevice { u64 handle; };

// -----------------------------------------------------------------------------
// -- snort common harness interfaces ------------------------------------------
// -----------------------------------------------------------------------------

SnortDevice snort_deviceCreateFromCommon(
	SnortCommonInterface const type,
	char const * const customLabel,
	char const * const romPath,
	i32 const argc,
	char const * const * const argv
);

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

// returns the number of frames that should be processed.
// User must call snort_updateFrame for the number of frames returned, followed
//   by a call to snort_endFrame.
// The code should look like this:
//   u64 framesToRun = snort_startFrame(device, memoryRegions);
//   for (u64 it = 0; it < framesToRun; ++ it) {
//     snort_updateFrame(device, memoryRegions);
//     myDevice.processFrame();
//   }
//   snort_endFrame(device);
u64 snort_startFrame(
	SnortDevice const device,
	SnortMemoryRegion const * memoryRegions
);

void snort_updateFrame(
	SnortDevice const device,
	SnortMemoryRegion const * memoryRegions
);

void snort_endFrame(SnortDevice const device);

// -----------------------------------------------------------------------------
// -- snort harness deterministic synchronization ------------------------------
// -----------------------------------------------------------------------------

u64 snort_rngU64(SnortDevice const device);
f32 snort_rngF32(SnortDevice const device);
