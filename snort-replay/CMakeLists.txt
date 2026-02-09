add_library(
	snort-replay
	STATIC
	src/playback.cpp
)

target_compile_options(
	snort-replay
	PRIVATE
		-Wall
)

target_include_directories(
	snort-replay
	PUBLIC
		include/
)

target_link_libraries(
	snort-replay
	snort
)
