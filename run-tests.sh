#!/opt/homebrew/bin/fish

set chip8_files \
	"test-1" \
	"test-2" \
	"test-3" \
	"test-4" \
	"test-5" \
	"test-6" \
	"test-7" \
	"test-8" \
	"test-9" \
	"test-10" \
	"test-11" \
	"test-12" \
	"test-13" \
	"test-14" \
	"test-15" \
	"test-16" \
	"test-17" \
	"test-18" \
	"test-19" \
	"test-20" \
	"test-21" \
	"test-22" \
	"test-23" \
	"test-24" \
	"test-25" \

# generate reference output for each test file
#for file in $chip8_files
#	./install/bin/chip8-snort rom-suite/tests/chip8/$file.ch8
#	./install/bin/chip8-reference-1 rom-suite/tests/chip8/$file.ch8
#end

# validate with comparison tool
for file in $chip8_files
	./install/bin/snort-compare \
		"replays/snort-chip8-$file.rpl" \
		"replays/griffin-$file.rpl"
end
