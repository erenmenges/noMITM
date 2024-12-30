cmake_minimum_required(VERSION 3.10)
project(SecureComm)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable warnings and security flags
if(MSVC)
    add_compile_options(/W4 /WX /sdl)
else()
    add_compile_options(-Wall -Wextra -Werror -fstack-protector-strong)
endif()

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    src/Main.cpp
    src/Communication.cpp
    src/Crypto.cpp
    src/KeyManagement.cpp
    src/Logger.cpp
    src/NetworkStack.cpp
    src/OCSP.cpp
    src/Utils.cpp
)

# Header files
set(HEADERS
    include/Communication.hpp
    include/Crypto.hpp
    include/KeyManagement.hpp
    include/Logger.hpp
    include/NetworkStack.hpp
    include/OCSP.hpp
    include/SecureTypes.hpp
    include/Utils.hpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE 
    pthread
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Enable testing
enable_testing() 