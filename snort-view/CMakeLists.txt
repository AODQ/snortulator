add_executable(
	snort-view
	src/view.cpp
)

target_compile_options(
	snort-view
	PRIVATE
		-Wall
)

target_link_libraries(snort-view raylib imgui snort-replay imguifiledialog)

install(TARGETS snort-view DESTINATION bin)
