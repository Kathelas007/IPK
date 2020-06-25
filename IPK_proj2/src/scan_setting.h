/**
 * author: Muskova Katerina (xmusko00)
 * file: scan_setting.h
 */
#ifndef IPK_PROJ2_SCAN_SETTING_H
#define IPK_PROJ2_SCAN_SETTING_H

#include <string>
#include <cstring>
#include <getopt.h>
#include <vector>

using namespace std;

class SSetting {
    enum protocol {
        TCP, UDP
    };
private:
    void set_ports(const string &, protocol);

public:
    string interface = "";
    vector<int> tcp_ports;
    vector<int> udp_ports;
    string target = "";

    string help = "Port scanner\n"
                  "usage: {-i <interface>} --pu <port-ranges> --pt <port-ranges> [<domain-name> | <IP-address>] \n";

    void parse_setting(int, char **);

    void print_help();

    void print_setting();

    ~SSetting();

};

#endif //IPK_PROJ2_SCAN_SETTING_H
