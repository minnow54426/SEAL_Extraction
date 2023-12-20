aux_source_directory(. PIRExample_SRCS)
add_library(PIRExampleLIB STATIC ${PIRExample_SRCS})

# target_include_directories(PIRExampleLIB util)
target_link_libraries(PIRExampleLIB UTILLIB)