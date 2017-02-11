cmake_minimum_required(VERSION 2.8)

file(GLOB qstat_src
    "*.h"
    "*.c"
)

add_executable(qstat ${qstat_src})
target_link_libraries(qstat m)
