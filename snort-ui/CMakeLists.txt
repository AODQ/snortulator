add_library(
	snort-ui
	STATIC
	src/ui.cpp
)

target_compile_options(
	snort-ui
	PRIVATE
		-Wall
)

target_include_directories(
	snort-ui
	PUBLIC
		include/
)

target_link_libraries(
	snort-ui
		raylib
		imgui
		snort
)
