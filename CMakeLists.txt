cmake_minimum_required(VERSION 3.13) # Required by SEAL

project(sealExtraction)

find_package(SEAL 4.1 REQUIRED)

aux_source_directory(. DIR_SRCS)
add_executable(sealExtraction ${DIR_SRCS})

target_link_libraries(sealExtraction SEAL::seal)

# enable_testing()
# macro (do_test arg1 arg2 result)
#     add_test(test_${arg1}_${arg2} sealExtraction ${arg1} ${arg2})
#     set_tests_properties(test_${arg1}_${arg2}
#         PROPERTIES PASS_REGULAR_EXPRESSION ${result}
#     )
# endmacro(do_test)

# foreach(index RANGE 10)
#     foreach(value RANGE 10)
#         do_test(${index} ${value} ${value})
#     endforeach(value RANGE 10)
# endforeach(index RANGE 10)
