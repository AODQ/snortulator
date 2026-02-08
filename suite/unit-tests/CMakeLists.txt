add_executable(
	unit-tests
	src/source.cpp
)

target_compile_options(
	unit-tests
	PRIVATE
		-Wall
)

target_link_libraries(
	unit-tests
	PUBLIC
		snort
)

# install
install(
	TARGETS unit-tests
	RUNTIME DESTINATION bin
)
