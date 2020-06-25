/**
 * author: Muskova Katerina (xmusko00)
 * file: scan_exit.cpp
 */
#include "scan_exit.h"
#include <string>
#include <iostream>

using namespace std;

void exit_scanner(scanner_return_code return_code = OK, const string& msg = "") {
    cerr << msg << endl;
    exit(return_code);
}