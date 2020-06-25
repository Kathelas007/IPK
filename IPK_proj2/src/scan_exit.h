/**
 * author: Muskova Katerina (xmusko00)
 * file: scan_exit.h
 */
#ifndef IPK_PROJ2_SCAN_EXIT_H
#define IPK_PROJ2_SCAN_EXIT_H

#include <string>

using namespace std;

enum scanner_return_code {
    OK, ARG_ERR, NO_INTERFACE_ERR, TARGET_ERR, INTERN_ERR
};

void exit_scanner(scanner_return_code, const string&);

#endif //IPK_PROJ2_SCAN_EXIT_H
