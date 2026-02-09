add_library(
	snort-harness
	STATIC
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
		imgui
		raylib
		snort
		snort-replay
		snort-ui
)
