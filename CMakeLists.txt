cmake_minimum_required(VERSION 3.16)
project(PESandbox)
set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(pesandbox
    src/main.cpp
    src/pe_parser.cpp
    src/import_analyzer.cpp
    src/string_extractor.cpp
    src/entropy.cpp
    report/report_writer.cpp     
)


