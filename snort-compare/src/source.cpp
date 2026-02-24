#include <snort/snort.h>

#include <snort-replay/fs.hpp>
#include <snort-replay/validation.hpp>

#include <stdio.h>

i32 main(i32 argc, char* argv[])
{
	if (argc <= 2) {
		printf("usage: %s <replay file> <comparison replay file>\n", argv[0]);
		return 1;
	}

	SnortFs::ReplayFile oriReplayFile = SnortFs::replay_open(argv[1]);
	SnortFs::ReplayFile cmpReplayFile = SnortFs::replay_open(argv[2]);
	if (oriReplayFile.handle == 0) {
		printf("failed to open replay file %s\n", argv[1]);
		return 1;
	}
	if (cmpReplayFile.handle == 0) {
		printf("failed to open replay file %s\n", argv[2]);
		SnortFs::replay_close(oriReplayFile);
		return 1;
	}

	size_t const fc = SnortFs::validateMemory(oriReplayFile, cmpReplayFile);
	if (fc == ~0u) {
		printf("->%s: PASS\n", argv[1]);
		return 0;
	}
	printf("->%s: FAIL, first invalid frame: %zu\n", argv[1], fc);
}
