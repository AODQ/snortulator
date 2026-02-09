#include <snort/snort.h>

#include <rlImGui.h>
#include <raylib.h>
#include <imgui.h>

#ifdef __cplusplus
extern "C" {
#endif

void snort_displayInitialize();
void snort_displayDestroy();
void snort_displayFrameBegin();
void snort_displayFrameEnd();

void snort_displayMemory(
	size_t regions,
	SnortMemoryRegionCreateInfo const * regionInfo,
	u8 const * const * regionData
);

#ifdef __cplusplus
} // extern "C"
#endif
