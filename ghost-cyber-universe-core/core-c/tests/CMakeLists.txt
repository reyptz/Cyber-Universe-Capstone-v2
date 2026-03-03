# Tests for ghost-core library

add_executable(test_ghost_core
    test_payload.c
)

target_link_libraries(test_ghost_core
    ghost_core_static
    m
    pthread
    crypto
    ssl
)

add_test(NAME ghost_core_test COMMAND test_ghost_core)
