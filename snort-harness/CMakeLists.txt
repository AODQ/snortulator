add_library(
	snort-harness
	STATIC
	src/imgui-display.cpp
	src/random.cpp
	src/device.cpp
)

target_compile_options(
	snort-harness
	PRIVATE
		-Wall
)

target_include_directories(
	snort-harness
	PUBLIC
		include/
)

target_link_libraries(
	snort-harness
	snort
	raylib
	imgui
	snort-replay
)
