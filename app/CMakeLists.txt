add_executable(${OTP_EXE}
				"main.c")

target_include_directories(${OTP_EXE} PUBLIC
							${HEADER_DIRS})

find_package(Threads REQUIRED)
find_library(POSIX_TIMER_LIBRARY rt)

message(${POSIX_TIMER_LIBRARY})

target_link_libraries(${OTP_EXE} PUBLIC
						${OTP_LIBRARY}
						${POSIX_TIMER_LIBRARY}
						Threads::Threads)