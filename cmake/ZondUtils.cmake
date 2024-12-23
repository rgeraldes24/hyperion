#
# renames the file if it is different from its destination
include(CMakeParseArguments)
#
macro(replace_if_different SOURCE DST)
	set(extra_macro_args ${ARGN})
	set(options CREATE)
	set(one_value_args)
	set(multi_value_args)
	cmake_parse_arguments(REPLACE_IF_DIFFERENT "${options}" "${one_value_args}" "${multi_value_args}" "${extra_macro_args}")

	if (REPLACE_IF_DIFFERENT_CREATE AND (NOT (EXISTS "${DST}")))
		file(WRITE "${DST}" "")
	endif()

	execute_process(COMMAND ${CMAKE_COMMAND} -E compare_files "${SOURCE}" "${DST}" RESULT_VARIABLE DIFFERENT OUTPUT_QUIET ERROR_QUIET)

	if (DIFFERENT)
		execute_process(COMMAND ${CMAKE_COMMAND} -E rename "${SOURCE}" "${DST}")
	else()
		execute_process(COMMAND ${CMAKE_COMMAND} -E remove "${SOURCE}")
	endif()
endmacro()

macro(zond_default_option O DEF)
	if (DEFINED ${O})
		if (${${O}})
			set(${O} ON)
		else ()
			set(${O} OFF)
		endif()
	else ()
		set(${O} ${DEF})
	endif()
endmacro()

function(detect_stray_source_files FILELIST DIRECTORY)
	if(CMAKE_VERSION VERSION_LESS 3.12)
		file(GLOB sources RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "${DIRECTORY}/*.cpp" "${DIRECTORY}/*.h")
	else()
		file(GLOB sources RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "${DIRECTORY}/*.cpp" "${DIRECTORY}/*.h")
	endif()
	foreach(path IN LISTS FILELIST)
		list(REMOVE_ITEM sources ${path})
	endforeach()
	list(LENGTH sources leftover_sources)
	if (leftover_sources)
		message(SEND_ERROR "The following source files are present but are not compiled: ${sources}")
	endif()
endfunction(detect_stray_source_files)

# CreateExportedFunctionsForEMSDK(OUTPUT_VARIABLE Symbol1 Symbol2 ... SymbolN)
function(CreateExportedFunctionsForEMSDK OUTPUT_VARIABLE)
	list(TRANSFORM ARGN PREPEND "\"_")
	list(TRANSFORM ARGN APPEND "\"")
	list(JOIN ARGN "," ARGN)
	set(${OUTPUT_VARIABLE} "[${ARGN}]" PARENT_SCOPE)
endfunction()
