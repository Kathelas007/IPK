CC=g++
FLAGS=-g -Wall -pedantic -std=c++11
FILE=ipk-scan

all:
	$(CC) $(FLAGS) $(FILE).cpp scan_exit.cpp scan_exit.h scan_setting.cpp scan_setting.h udp_scanner.cpp udp_scanner.h tcp_scanner.cpp tcp_scanner.h -o $(FILE) -lpcap -pthread
