cmake_minimum_required(VERSION 3.24 FATAL_ERROR) # 3.24 for vk components
cmake_policy(VERSION 3.24)

project(snort_suite LANGUAGES CXX)

# c++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# add ccache if found
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK    ccache)
  message("*-- CCACHE found, will use")
endif()

## add include what you use if found
find_program(iwyu_path "/usr/local/bin/" NAMES include-what-you-use iwyu)
if(iwyu_path)
  message("*-- include-what-you-use found, will use")
  set_property(GLOBAL PROPERTY CXX_INCLUDE_WHAT_YOU_USE ${iwyu_path})
endif()

# raylib
find_package(raylib REQUIRED)
# openal (raylib audio doesn't work)
find_package(OpenAL REQUIRED)

# imgui + rlimgui
set(IMGUI_DIR external/imgui)
set(RLIMGUI_DIR external/rlImGui)
add_library(
	imgui
	STATIC
		${IMGUI_DIR}/imgui.cpp
		${IMGUI_DIR}/imgui_draw.cpp
		${IMGUI_DIR}/imgui_tables.cpp
		${IMGUI_DIR}/imgui_widgets.cpp
		${RLIMGUI_DIR}/rlImGui.cpp
)
target_link_libraries(imgui PRIVATE raylib)
target_include_directories(imgui PUBLIC ${IMGUI_DIR} ${RLIMGUI_DIR})



# snort
add_subdirectory(snort)
add_subdirectory(snort-replay)
#
# suite
add_subdirectory(suite/unit-tests)
#
## core library
#add_subdirectory(core)
#
## emulators
#add_subdirectory(emulators/chip-8)
#
## reference emulators
#add_subdirectory(reference-emulators/chip-8)
