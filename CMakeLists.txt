# CMakeList.txt : CMake project for HOTP, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project(HOTP VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD          17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS        OFF)

set(OTP_LIBRARY otp_lib)

set(OTP_EXE genotp)


set(HEADER_DIR "${CMAKE_SOURCE_DIR}/include")
set(EXTERNAL_DIR "${CMAKE_SOURCE_DIR}/external")
set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
include(AddGitSubmodule)

add_git_submodule(external openssl https://github.com/openssl/openssl.git)

set(OPENSSL_PATH "${EXTERNAL_DIR}/openssl")

if (NOT EXISTS "${OPENSSL_PATH}/CMakeLists.txt")

        include(ExternalProject)

        if(CMAKE_SYSTEM_NAME STREQUAL "Windows")

            # Add the directory containing Perl to the CMAKE_PREFIX_PATH variable
            list(APPEND CMAKE_PREFIX_PATH "E://Strawberry_Perl//perl//bin")
            find_package(Perl)

            if(${PERL_FOUND})
               message(STATUS "Found perl: ${PERL_EXECUTABLE}")
            else()
                message(FATAL_ERROR "Perl executable not found.")
            endif()
	        
	        set(CONFIGURE_COMMAND ${PERL_EXECUTABLE} Configure --prefix=${OPENSSL_PATH}/build --openssldir=${OPENSSL_PATH}/build/ssl )
         
        elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set(CONFIGURE_COMMAND ./Configure --prefix=${OPENSSL_PATH}/build --openssldir=${OPENSSL_PATH}/build/ssl )

        endif()
        
        find_program(MAKE_EXE NAMES nmake make)
        
        if(MAKE_EXE)
            message(STATUS "Found platform specific make executable: ${MAKE_EXE}")
        else()
            message(FATAL_ERROR "nmake not found. Please make sure it is installed.")
        endif()


        if(NOT EXISTS "${OPENSSL_PATH}/build")

            execute_process(
                COMMAND ${CONFIGURE_COMMAND}
                WORKING_DIRECTORY ${OPENSSL_PATH}
                RESULT_VARIABLE result
            )


            if(result)
                message(FATAL_ERROR "Configuration Command failed.")
            endif()

            execute_process(
                COMMAND ${MAKE_EXE}
                WORKING_DIRECTORY ${OPENSSL_PATH}
                RESULT_VARIABLE result
            )

            if(result)
                message(FATAL_ERROR "make Command failed.")
            endif()

            set(MAKE_EXE_INSTALL ${MAKE_EXE} install)

            execute_process(
                COMMAND ${MAKE_EXE_INSTALL}
                WORKING_DIRECTORY ${OPENSSL_PATH}
                RESULT_VARIABLE result
            )

            if(result)
                message(FATAL_ERROR "make install Command failed.")
            endif()

        endif()

        #This will be executed during build time not CMake Time.
        #ExternalProject_Add(
        #    OpenSSL_deps
        #    PREFIX ${CMAKE_BINARY_DIR}/external
        #    DOWNLOAD_COMMAND ""  # No download command since we're not downloading, assuming Makefile is already present
        #    SOURCE_DIR ${OPENSSL_PATH}  # Specify the path to the directory containing the Makefile
        #    BINARY_DIR ${OPENSSL_PATH}/lib #All the build file will be present here, if BUILD_IN_SOURCE is not set.
        #    CONFIGURE_COMMAND ${CONFIGURE_COMMAND}  # No configure command needed for Makefile-based projects
        #    BUILD_COMMAND ${MAKE_EXE}  # Command to build the project using make
        #    INSTALL_COMMAND ""  # No install command needed for Makefile-based projects
        #    BUILD_IN_SOURCE 0  # Build the project in the source directory
        #)

endif()


set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL PATHS ${OPENSSL_PATH})

if( OPENSSL_FOUND )
    message(STATUS "OpenSSL found: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL found: ${OPENSSL_CRYPTO_LIBRARY}")
    message(STATUS "OpenSSL found: ${OPENSSL_SSL_LIBRARY}")
    message(STATUS "OpenSSL found: ${OPENSSL_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

set(OPENSSL_LIB
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${OPENSSL_LIBRARIES})

set(OPENSSL_HEADER
        ${OPENSSL_INCLUDE_DIR})

add_subdirectory(src)
add_subdirectory(app)

# TODO: Add tests and install targets if needed.
