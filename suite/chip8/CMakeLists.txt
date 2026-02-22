add_executable(
	chip8
	src/device.cpp
	src/source.cpp
)

target_compile_options(
	chip8
	PRIVATE
		-Wall
)

target_link_libraries(
	chip8
	PUBLIC
		snort
		snort-replay
		snort-harness
)

# install
install(
	TARGETS chip8
	RUNTIME DESTINATION bin
)
