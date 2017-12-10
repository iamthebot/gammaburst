add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/crypto)
add_library(gammaburst SHARED ${CRYPTO_SRCS} ../include/key_store.hpp crypto/key_store.cpp)