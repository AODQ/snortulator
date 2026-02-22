#include <snort/snort-ui.h>

namespace gui {
	void displayDeviceChip8(
		size_t regions,
		SnortMemoryRegionCreateInfo const * regionInfo,
		u8 const * const * regionData,
		u8 const * const * optRegionDataCmp
	);
}
