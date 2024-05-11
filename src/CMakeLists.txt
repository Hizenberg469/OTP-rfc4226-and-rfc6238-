add_library(${OTP_LIBRARY} STATIC
			"rfc4226.c"
			"rfc6238.c")

target_include_directories(${OTP_LIBRARY} PUBLIC
							${HEADER_DIR}
							${OPENSSL_HEADER})

target_link_libraries(${OTP_LIBRARY} PUBLIC
						${OPENSSL_LIB}
						m)