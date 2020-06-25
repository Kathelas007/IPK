/**
 * author: Muskova Katerina (xmusko00)
 * file: scan_setting.cpp
 */
#include <iostream>
#include "scan_setting.h"
#include "scan_exit.h"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <getopt.h>
#include <cctype>
#include <algorithm>

using namespace std;

bool is_number(const string &digit) {
    if (digit.empty()) return false;

    for (char i : digit) {
        if (!isdigit((int) i)) return false;
    }
    return true;
}

//  --pt 22 nebo --pu 1-65535 nebo --pt 22,23,24
void SSetting::set_ports(const string &port_opt, protocol prot) {
    stringstream input(port_opt);
    vector<string> port_groups;
    string group;

    vector<int> all_ports;

    while (getline(input, group, ',')) {
        port_groups.push_back(group);
    }

    for (auto &item : port_groups) {
        int index;
        if ((index = item.find('-', 0)) != -1) {

            string num_str = item.substr(0, index);
            if (!is_number(num_str)) {
                this->print_help();
                exit_scanner(ARG_ERR, "Can not convert to port number.");
            }
            int first_port = (int) strtol(num_str.c_str(), nullptr, 0);

            num_str = item.substr(index + 1, item.length() - index - 1);
            if (!is_number(num_str)) {
                this->print_help();
                exit_scanner(ARG_ERR, "Can not convert to port number.");
            }
            int second_port = (int) strtol(num_str.c_str(), nullptr, 0);

            for (int port_num = first_port; port_num <= second_port; port_num++) {
                all_ports.push_back(port_num);
            }
        } else {
            if (!is_number(item)) {
                this->print_help();
                exit_scanner(ARG_ERR, "Can not convert to port number.");
            }
            int port = (int) strtol(item.c_str(), nullptr, 0);
            all_ports.push_back(port);
        }
    }

     //uniq, sort
     if(!all_ports.empty()){
         sort(all_ports.begin(), all_ports.end());
         all_ports.erase(unique(all_ports.begin(), all_ports.end()), all_ports.end());
     }

     // ranges
    if (!all_ports.empty()) {
        if (all_ports.back() > 65535 or all_ports.at(0) < 1) {
            exit_scanner(ARG_ERR, "Port range is <1, 65535>");
        }
    }


    if (prot == TCP) this->tcp_ports.assign(all_ports.begin(), all_ports.end());
    else this->udp_ports.assign(all_ports.begin(), all_ports.end());
}

void SSetting::parse_setting(int argc, char **argv) {
    int o_option_index = 0;
    int o_option;

    // todo domain_name, ip-address
    static struct option long_opts[] = {
            {"interface", required_argument, 0, 'i'},
            {"pt",        required_argument, 0, 't'},
            {"pu",        required_argument, 0, 'u'},
            {"help",      no_argument,       0, 'h'},
            {0, 0,                           0, 0}
    };

    opterr = 0;
    while ((o_option = getopt_long(argc, argv, ":h::i:t:u:", long_opts, &o_option_index)) != -1) {
        switch (o_option) {
            case 'i':
                this->interface = optarg;
                break;
            case 't':
                this->set_ports(optarg, TCP);
                break;
            case 'u':
                this->set_ports(optarg, UDP);
                break;
            case 'h':
                this->print_help();
                exit_scanner(OK, "");
                break;
            case ':':
                this->print_help();
                exit_scanner(ARG_ERR, "Required argument value missing.");
            case '?':
                this->print_help();
                exit_scanner(ARG_ERR, "Can not recognize o_option.");
                break;
            default:
                this->print_help();
                exit_scanner(ARG_ERR, "Can not get o_option.");
                break;
        }
    }

    if (optind != argc - 1) {
        this->print_help();
        exit_scanner(ARG_ERR, "One target (domain name or ip address) expected");
    }
    this->target = argv[optind];

    if (this->tcp_ports.empty() and this->udp_ports.empty()) {
        this->print_help();
        exit_scanner(ARG_ERR, "At least one of --pt or --pu is expected.");
    }
}

void SSetting::print_help() {
    printf("%s", this->help.c_str());
}

void SSetting::print_setting() {
    printf("Interface: %s\n", this->interface.c_str());
    printf("TCP ports: ");

    for (int &tcp_port : this->tcp_ports)
        cout << tcp_port << ' ';

    printf("\nUDP ports: ");

    for (int &tcp_port : this->udp_ports)
        cout << tcp_port << ' ';

    printf("\nTarget: %s\n", this->target.c_str());
}

SSetting::~SSetting() {

}






