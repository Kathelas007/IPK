/**
 * author: Muskova Katerina (xmusko00)
 * file: ipk-scan.cpp
 */

#include <iostream>
#include <cstdio>
#include <cstdlib>

#include <string>
#include <utility>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <ifaddrs.h>

#include <netdb.h>
#include <arpa/inet.h>


#include "scan_exit.h"
#include "scan_setting.h"
#include "udp_scanner.h"
#include "tcp_scanner.h"

// todo catch  ctrl+c , delete setting

string get_IPvX_interfaces(string &interface_name, int ip_type) {

    struct ifaddrs *interface, *tmp;

    //https://linux.die.net/man/3/getifaddrs
    if (getifaddrs(&interface) == -1) exit_scanner(INTERN_ERR, "Function getifaddrs()  failed.");

    for (tmp = interface; tmp != nullptr; tmp = tmp->ifa_next) {

        //no loopback, must be running, TCP/UPD protocol
        if (!(tmp->ifa_flags & IFF_LOOPBACK) and (tmp->ifa_flags & IFF_RUNNING) and
            (tmp->ifa_addr) and
            (tmp->ifa_addr->sa_family == ip_type)) {

            if (interface_name.empty() or strcmp(interface_name.c_str(), tmp->ifa_name) == 0) break;
        }
    }

    if (!tmp) {
        freeifaddrs(interface);
        exit_scanner(NO_INTERFACE_ERR, "Can not find suitable interface.");
    }

    interface_name = tmp->ifa_name;

    //https://linux.die.net/man/3/getnameinfo
    char host_buf[150];
    int interface_family = tmp->ifa_addr->sa_family;
    socklen_t socket_len;

    if (interface_family == AF_INET) {
        socket_len = sizeof(sockaddr_in);
    } else {
        socket_len = sizeof(sockaddr_in6);
    }

    int get_name_res = getnameinfo(tmp->ifa_addr, socket_len,
                                   host_buf, sizeof(host_buf),
                                   nullptr, 0, NI_NUMERICHOST);

    if (get_name_res != 0) {
        freeifaddrs(interface);
        exit_scanner(INTERN_ERR, "Function getnameinfo() failed");
    }

    freeifaddrs(interface);
    string interface_ip_address = host_buf;
    return interface_ip_address;
}

string get_interface_IP(string &interface_name, int &ip_type) {
    string interface_ip;
    if (ip_type != AF_UNSPEC) {
        interface_ip = get_IPvX_interfaces(interface_name, ip_type);
    } else {
        interface_ip = get_IPvX_interfaces(interface_name, AF_INET6);
        if (interface_ip.empty()) {
            interface_ip = get_IPvX_interfaces(interface_name, AF_INET);
            ip_type = AF_INET;
        } else {
            ip_type = AF_INET6;
        }
    }

    if (interface_ip.empty()) {
        exit_scanner(INTERN_ERR, "Can not find suitable interface.");
    }

    return interface_ip;
}

bool is_valid_IPvX(const string &address, int type) {
    //http://man7.org/linux/man-pages/man3/inet_pton.3.html
    struct sockaddr_in sa;
    int result = inet_pton(type, address.c_str(), &(sa.sin_addr));
    return result == 1;
}

string address_to_text_form(addrinfo *src) {
    //http://man7.org/linux/man-pages/man3/inet_ntop.3.html
    //https://stackoverflow.com/questions/1966687/bogus-ip-address-from-getaddrinfo-inet-ntop

    char dest[150];
    inet_ntop(src->ai_family, &((const sockaddr_in *) src->ai_addr)->sin_addr, dest, sizeof(dest));

    string text_addr = dest;
    return text_addr;
}

string domain_to_address(const string &domain, int &ip_type) {
    //http://man7.org/linux/man-pages/man3/getaddrinfo.3.html, first example
    struct addrinfo *result;
    struct addrinfo hints{};
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;

    int res = getaddrinfo(domain.c_str(), nullptr, &hints, &result);

    if ((res == 0) and ((ip_type == AF_UNSPEC) or ip_type == AF_INET)) {
        ip_type = AF_INET;
        string address = address_to_text_form(result);
        freeaddrinfo(result);
        return address;
    }

    hints.ai_family = AF_INET6;

    res = getaddrinfo(domain.c_str(), nullptr, &hints, &result);

    if ((res == 0) and ((ip_type == AF_UNSPEC) or ip_type == AF_INET6)) {
        ip_type = AF_INET6;
        string address = address_to_text_form(result);
        freeaddrinfo(result);
        return address;
    }

    freeaddrinfo(result);
    exit_scanner(TARGET_ERR, "Can not convert target domain name to IP address.");

    return "";

}

string get_target_ip(string target, int &ip_type) {
    // is IPv4
    if (is_valid_IPvX(target, AF_INET)) {
        if (ip_type == AF_INET or ip_type == AF_UNSPEC) {
            ip_type = AF_INET;
            return target;
        } else {
            exit_scanner(TARGET_ERR, "Target does not have IPv4.");
        }
    }
    // is IPv6
    if (is_valid_IPvX(target, AF_INET6)) {
        if (ip_type == AF_INET6 or ip_type == AF_UNSPEC) {
            ip_type = AF_INET6;
            return target;
        } else {
            exit_scanner(TARGET_ERR, "Target does not have IPv6.");
        }
    }

    // is domain_name
    return domain_to_address(target, ip_type);

}

int main(int argc, char **argv) {
    SSetting setting;
    setting.parse_setting(argc, argv);

    string interface_IP;

    int ipv_type = AF_UNSPEC;

    setting.target = get_target_ip(setting.target, ipv_type);
    interface_IP = get_interface_IP(setting.interface, ipv_type);

    cout << "\n";
    cout << "PROT\tPORT\tSTATUS\n";

    UDP::scan_udp(setting.interface, setting.target, setting.udp_ports, ipv_type);
    TCP::scan_tcp(interface_IP, setting.interface, setting.target, setting.tcp_ports, ipv_type);

    return 0;
}