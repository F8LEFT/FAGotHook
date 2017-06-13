set(ProjectName FAGotHook)

aux_source_directory(. ROOT_SRC)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(FA_EXTLIB log)
endif()

if(FA_STATIC)
    add_definitions(-DFA_STATIC)
    add_library( ${ProjectName}
             STATIC
             ${ROOT_SRC})
else()
    add_library( ${ProjectName}
             SHARED
             ${ROOT_SRC} )
endif()

target_link_libraries( ${ProjectName}
                       ${FA_EXTLIB} dl)
