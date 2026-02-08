#include "device.hpp"

// --

u64 snort_rngU64(SnortDevice const deviceHandle) {
	auto & device = *(snort::Device *)(uintptr_t)(deviceHandle.handle);
	// simple xorshift rng
	u64 const x = device.rngSeed;
	device.rngSeed = x ^ (x << 13);
	device.rngSeed = device.rngSeed ^ (device.rngSeed >> 7);
	device.rngSeed = device.rngSeed ^ (device.rngSeed << 17);
	return device.rngSeed;
}

// --

f32 snort_rngF32(SnortDevice const device) {
	u64 randInt = snort_rngU64(device);
	return static_cast<f32>(randInt) / static_cast<f32>(UINT64_MAX);
}
