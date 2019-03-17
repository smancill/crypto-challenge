FetchContent_Declare(
  base64
  GIT_REPOSITORY https://github.com/ReneNyffenegger/cpp-base64
  GIT_TAG master
  GIT_SHALLOW TRUE
)

FetchContent_GetProperties(base64)

if(NOT base64_POPULATED)
  FetchContent_Populate(base64)

  add_library(base64 STATIC ${base64_SOURCE_DIR}/base64.cpp)
  target_include_directories(base64 PUBLIC ${base64_SOURCE_DIR})
endif()
