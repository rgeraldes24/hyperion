# CMAKE macros to set default CMAKE options and to show the
# resulting configuration.

macro(configure_project)
	set(NAME ${PROJECT_NAME})

	# features
	zond_default_option(COVERAGE OFF)
	zond_default_option(OSSFUZZ OFF)

	# components
	zond_default_option(TESTS ON)
	zond_default_option(TOOLS ON)

	# Define a matching property name of each of the "features".
	foreach(FEATURE ${ARGN})
		set(SUPPORT_${FEATURE} TRUE)
	endforeach()

	include(ZondBuildInfo)
	create_build_info(${NAME})
	print_config(${NAME})
endmacro()

macro(print_config NAME)
	message("")
	message("------------------------------------------------------------------------")
	message("-- Configuring ${NAME} ${PROJECT_VERSION}")
	message("------------------------------------------------------------------------")
	message("--                  CMake Version                            ${CMAKE_VERSION}")
	message("-- CMAKE_BUILD_TYPE Build type                               ${CMAKE_BUILD_TYPE}")
	message("-- TARGET_PLATFORM  Target platform                          ${CMAKE_SYSTEM_NAME}")
	message("--------------------------------------------------------------- features")
	message("-- COVERAGE         Coverage support                         ${COVERAGE}")
	message("------------------------------------------------------------- components")
if (SUPPORT_TESTS)
	message("-- TESTS            Build tests                              ${TESTS}")
endif()
if (SUPPORT_TOOLS)
	message("-- TOOLS            Build tools                              ${TOOLS}")
endif()
	message("------------------------------------------------------------------ flags")
	message("-- OSSFUZZ                                                   ${OSSFUZZ}")
	message("------------------------------------------------------------------------")
	message("")
endmacro()
