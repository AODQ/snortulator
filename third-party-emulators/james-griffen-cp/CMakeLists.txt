project(CHIP_8_Emulator)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES src/main.cpp src/chip8.cpp)
add_executable(jamesGriffinChip8 ${SOURCE_FILES})

INCLUDE(FindPkgConfig)

PKG_SEARCH_MODULE(SDL2 REQUIRED sdl2)

INCLUDE_DIRECTORIES(${SDL2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(jamesGriffinChip8 ${SDL2_LIBRARIES} snort snort-harness)

install(
	TARGETS jamesGriffinChip8
	RUNTIME DESTINATION bin
)
