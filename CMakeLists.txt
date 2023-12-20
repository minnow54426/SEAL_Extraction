cmake_minimum_required(VERSION 3.13) # Required by SEAL

project(manipulateSEAL)

include_directories(.)
include_directories(${PROJECT_SOURCE_DIR}/util)
include_directories(${PROJECT_SOURCE_DIR}/extractExample)
include_directories(${PROJECT_SOURCE_DIR}/PIRExample)

add_subdirectory(util)
add_subdirectory(extractExample)
add_subdirectory(PIRExample)

aux_source_directory(. DIR_SRCS)
add_executable(manipulateSEAL ${DIR_SRCS})  

target_link_libraries(manipulateSEAL PIRExampleLIB extractExampleLIB)

find_package(SEAL 4.1 REQUIRED)
target_link_libraries(UTILLIB SEAL::seal)
