cmake_minimum_required(VERSION 3.26)
project(vmprotect_sdk LANGUAGES C CXX VERSION 1.0.0)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Normalize processor string for matching
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _proc)


# Determine 32/64 from target pointer size
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_bits 64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(_bits 32)
else()
    message(FATAL_ERROR "Unsupported pointer size: ${CMAKE_SIZEOF_VOID_P}")
endif()

# Build arch tag:
# - x86/x86_64 => 32 or 64
# - ARM/aarch64 => ARM32 or ARM64
if(_proc MATCHES "^(arm|armv[0-9].*|aarch64|arm64)$")
    set(ARCH_TAG "ARM${_bits}")   # ARM32 / ARM64
elseif(_proc MATCHES "^(x86|i[3-6]86|x86_64|amd64|x64)$")
    set(ARCH_TAG "${_bits}")      # 32 / 64
else()
    # fallback: still use bitness
    set(ARCH_TAG "${_bits}")
endif()

set(PROJECT_VARIANT "VMProtectSDK${ARCH_TAG}")
message(STATUS "Project variant: ${PROJECT_VARIANT}")

add_library(${PROJECT_NAME} SHARED
        include/VMProtectSDK.h
        source/VMProtectSDK.cpp
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang"))
    target_compile_definitions(${PROJECT_NAME} PRIVATE VMP_GNU)
endif()

if (WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE VMP_WIN)
endif ()

# Important for proper build/install usage
target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(vmprotect_sdk PRIVATE vmprotect_sdk_EXPORTS)
set_target_properties(${PROJECT_NAME} PROPERTIES
        OUTPUT_NAME "${PROJECT_VARIANT}"
        CXX_STANDARD 23
)

# -----------------------------
# Install rules
# -----------------------------

# Install library/binary
install(TARGETS ${PROJECT_NAME}
        EXPORT ${PROJECT_NAME}Targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}   # .dll/.exe on Windows
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}   # .so/.dylib
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}   # .lib/.a
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install public headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export targets for downstream find_package(... CONFIG)
install(EXPORT ${PROJECT_NAME}Targets
        FILE ${PROJECT_NAME}Targets.cmake
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Generate and install package config files
configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
)

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)