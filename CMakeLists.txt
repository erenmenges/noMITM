cmake_minimum_required(VERSION 3.10)
project(SecureComm)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
)

# Link pthread library
target_link_libraries(${PROJECT_NAME} PRIVATE pthread)

# Add compiler warnings
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)
endif() 