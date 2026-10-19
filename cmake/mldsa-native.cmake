# Only the native test hosts need cryptography; the compiler emits a precompile call.
include(FetchContent)

FetchContent_Declare(
    mldsa_native
    DOWNLOAD_DIR "${PROJECT_SOURCE_DIR}/deps/downloads"
    DOWNLOAD_NAME mldsa-native-2.0.0.tar.gz
    URL https://codeload.github.com/pq-code-package/mldsa-native/tar.gz/834a90d5e846ffa1e1611bd24e160bb2e9b86d35
    URL_HASH SHA256=7a9ab4d55912c2ab8f5d5de3b2123b5155b45ba1c848788c4aff90b62eaf0e4c
)

if (CMAKE_VERSION VERSION_LESS "3.14.0")
    FetchContent_GetProperties(mldsa_native)
    if (NOT mldsa_native_POPULATED)
        FetchContent_Populate(mldsa_native)
    endif()
else()
    FetchContent_MakeAvailable(mldsa_native)
endif()

# Use the portable C backend, without key generation, signing or an RNG dependency.
add_library(mldsa87 STATIC "${mldsa_native_SOURCE_DIR}/mldsa/mldsa_native.c")
target_include_directories(mldsa87 SYSTEM PUBLIC "${mldsa_native_SOURCE_DIR}/mldsa")
target_compile_definitions(mldsa87 PUBLIC
    MLD_CONFIG_PARAMETER_SET=87
    MLD_CONFIG_NAMESPACE_PREFIX=hyperion_mldsa87
    MLD_CONFIG_NO_KEYPAIR_API
    MLD_CONFIG_NO_SIGN_API
    MLD_CONFIG_NO_RANDOMIZED_API
)
set_target_properties(mldsa87 PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
