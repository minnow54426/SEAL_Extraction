aux_source_directory(. extractExample_SRCS)
add_library(extractExampleLIB STATIC ${extractExample_SRCS})

# target_include_directories(extractExampleLIB ./util)
target_link_libraries(extractExampleLIB UTILLIB)