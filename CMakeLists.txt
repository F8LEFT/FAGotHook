set(ProjectName FAGotHook)


if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(FA_EXTLIB log)
endif()

if(FA_STATIC)
    add_definitions(-DFA_STATIC)
    add_library( ${ProjectName}
             STATIC
             FAGotHook.cpp)
else()
    add_library( ${ProjectName}
             SHARED
             FAGotHook.cpp main.cpp)
endif()

target_link_libraries( ${ProjectName}
                       ${FA_EXTLIB} dl)
