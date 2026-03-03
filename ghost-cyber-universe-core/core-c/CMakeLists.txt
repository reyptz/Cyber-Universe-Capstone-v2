cmake_minimum_required(VERSION 3.20)
project(ghost-core VERSION 0.1.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags for performance and security
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -fPIC -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")

# Debug flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -DDEBUG")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Source files (collect all C implementations automatically)
file(GLOB GHOST_CORE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

# Header files
set(GHOST_CORE_HEADERS
    include/ghost_core.h
    include/payload.h
    include/crypto.h
    include/syscalls.h
    include/ffi.h
)

# Create shared library
add_library(ghost_core SHARED ${GHOST_CORE_SOURCES})

# Create static library
add_library(ghost_core_static STATIC ${GHOST_CORE_SOURCES})

# Set target properties
set_target_properties(ghost_core PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${GHOST_CORE_HEADERS}"
)

set_target_properties(ghost_core_static PROPERTIES
    VERSION ${PROJECT_VERSION}
    PUBLIC_HEADER "${GHOST_CORE_HEADERS}"
)

# Link libraries
target_link_libraries(ghost_core m pthread crypto ssl)
target_link_libraries(ghost_core_static m pthread crypto ssl)

# Installation
install(TARGETS ghost_core ghost_core_static
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# Tests
enable_testing()
add_subdirectory(tests)

# Package configuration
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ghost_core-config-version.cmake"
    VERSION ${PROJECT_VERSION}
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/ghost_core-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ghost_core-config.cmake"
    INSTALL_DESTINATION lib/cmake/ghost_core
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ghost_core-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ghost_core-config-version.cmake"
    DESTINATION lib/cmake/ghost_core
)

cmake_minimum_required(VERSION 3.13)
project(GenjutsuPolymorphicPass)

# Find LLVM
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Compilation flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")

# Add the pass library
add_library(PolymorphicPass MODULE
    PolymorphicPass.cpp
)

# Link against LLVM libraries
llvm_map_components_to_libnames(llvm_libs support core irreader)
target_link_libraries(PolymorphicPass ${llvm_libs})

# Set output directory
set_target_properties(PolymorphicPass PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Installation
install(TARGETS PolymorphicPass
    LIBRARY DESTINATION lib
)

# Print build information
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C++ Flags: ${CMAKE_CXX_FLAGS}")
