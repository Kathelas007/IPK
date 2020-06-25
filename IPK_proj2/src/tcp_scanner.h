/**
 * author: Muskova Katerina (xmusko00)
 * file: tcp_scanner.h
 */

#ifndef IPK_PROJ2_TCP_SCANNER_H
#define IPK_PROJ2_TCP_SCANNER_H

#include "string"
#include "vector"

#include<netinet/tcp.h>

using namespace std;

namespace TCP {

    //https://www.binarytides.com/raw-sockets-c-code-linux/
    struct pseudo_header {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;

        tcphdr tcp;
    };

    enum port_state {
        CLOSED, OPENDED, FILTRED
    };
    enum filter_type {
        ACK, RST
    };

    void scan_tcp(string, string, string, vector<int>, int);
}


#endif //IPK_PROJ2_TCP_SCANNER_H
