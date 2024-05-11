add_executable(${OTP_EXE}
				"main.c")

target_include_directories(${OTP_EXE} PUBLIC
							${HEADER_DIRS})

target_link_libraries(${OTP_EXE} PUBLIC
						${OTP_LIBRARY})