add_executable(
	chip8-snort
	src/device.cpp
	src/source.cpp
)

target_compile_options(
	chip8-snort
	PRIVATE
		-Wall
)

target_link_libraries(
	chip8-snort
	PUBLIC
		snort
		snort-replay
		snort-harness
)

# install
install(
	TARGETS chip8-snort
	RUNTIME DESTINATION bin
)
