cmake_minimum_required(VERSION 3.17)
project(nmap)

set(CMAKE_CXX_STANDARD 14)

include_directories(inc)
include_directories(/usr/local/opt/libpcap/include)

add_executable(nmap src/main.cpp)

#target_link_libraries(nmap libPcap++.a)
#target_link_libraries(nmap -L${CMAKE_CURRENT_SOURCE_DIR}/libPcap/)

target_link_libraries(nmap -L/usr/local/opt/libpcap/lib)
target_link_libraries(nmap libpcap.a)

find_package(Threads)
target_link_libraries(nmap ${CMAKE_THREAD_LIBS_INIT} )


#If you need to have libpcap first in your PATH run:
#echo 'export PATH="/usr/local/opt/libpcap/bin:$PATH"' >> ~/.zshrc

#For compilers to find libpcap you may need to set:
#export LDFLAGS="-L/usr/local/opt/libpcap/lib"
#export CPPFLAGS="-I/usr/local/opt/libpcap/include"

#For pkg-config to find libpcap you may need to set:
#export PKG_CONFIG_PATH="/usr/local/opt/libpcap/lib/pkgconfig"