add_library(
	snort
	STATIC
	src/imgui-display.cpp
	src/random.cpp
	src/device.cpp
)

target_compile_options(
	snort
	PRIVATE
		-Wall
)

target_include_directories(
	snort
	PUBLIC
		include/
)

target_link_libraries(
	snort
	raylib
	imgui
	snort-replay
)
