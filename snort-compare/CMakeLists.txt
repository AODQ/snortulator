add_executable(
	snort-compare
	src/source.cpp
)

target_compile_options(
	snort-compare
	PRIVATE
		-Wall
)

target_link_libraries(snort-compare snort-replay)

install(TARGETS snort-compare DESTINATION bin)
