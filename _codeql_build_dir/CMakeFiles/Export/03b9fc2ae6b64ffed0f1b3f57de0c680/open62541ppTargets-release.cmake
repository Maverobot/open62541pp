#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "open62541pp::open62541pp" for configuration "Release"
set_property(TARGET open62541pp::open62541pp APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(open62541pp::open62541pp PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libopen62541pp.a"
  )

list(APPEND _cmake_import_check_targets open62541pp::open62541pp )
list(APPEND _cmake_import_check_files_for_open62541pp::open62541pp "${_IMPORT_PREFIX}/lib/libopen62541pp.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
