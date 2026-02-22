#include <snort/snort.h>

// --

u64 snort_dtByteCount(SnortDt const dt) {
	switch (dt) {
		case kSnortDt_u8: return 1u;
		case kSnortDt_u16: return 2u;
		case kSnortDt_u32: return 4u;
		case kSnortDt_u64: return 8u;
		case kSnortDt_i8: return 1u;
		case kSnortDt_i16: return 2u;
		case kSnortDt_i32: return 4u;
		case kSnortDt_i64: return 8u;
		case kSnortDt_f32: return 4u;
		case kSnortDt_string: return 1u;
		case kSnortDt_r1: return 1u;
		case kSnortDt_r8: return 1u;
		case kSnortDt_rgba8: return 4u;
		default: return 1u;
	}
}
