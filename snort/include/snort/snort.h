#pragma once

#if defined(__cplusplus)
#include <cstdint>
#include <cstddef>
#else
#include <stdint.h>
#include <stddef.h>
#endif

// this is a C-API for an emulator framework which interfaces to a display
//   and comparing memory to other emulators over shmem

#if defined(__cplusplus)
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;
using f32 = float;
using f64 = double;
#else
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef float f32;
typedef double f64;
#endif

// -----------------------------------------------------------------------------

#define SnortAssert(x) \
	if (!(x)) { \
		printf("Snort assertion failed: %s (%s:%d)\n", #x, __FILE__, __LINE__); \
		std::abort(); \
	}

// -----------------------------------------------------------------------------
// -- snort device creation ----------------------------------------------------
// -----------------------------------------------------------------------------

enum SnortDt {
  kSnortDt_u8,
  kSnortDt_u16,
  kSnortDt_u32,
  kSnortDt_u64,
  kSnortDt_i8,
  kSnortDt_i16,
  kSnortDt_i32,
  kSnortDt_i64,
  kSnortDt_f32,
  // imadata type
  kSnortDt_r8,
  kSnortDt_rgba8,
};

u64 snort_dtByteCount(SnortDt const dt);

// this could be a register, ram, vram, sprite memory, display, etc.
struct SnortMemoryRegionCreateInfo {
	SnortDt dataType;
	size_t elementCount;
	// elements to display per row, 0=flag
	size_t elementDisplayRowStride;
	char const * label;
};
