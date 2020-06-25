/**
 * author: Muskova Katerina (xmusko00)
 * file: udp_scanner.cpp
 */

#include "string"
#include "vector"
#include "cstring"
#include "map"

#include <unistd.h>

#include "scan_exit.h"
#include "udp_scanner.h"
#include "scan_exit.h"

#include <sys/socket.h>

#include <pcap/pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <thread>

namespace UDP {

    string interface_name;
    string target_IP;
    vector<int> ports;
    int ip_type;

    int current_port;

    map<int, bool> results;

    void clear_and_exit(scanner_return_code, string);

    // get pointer to pcap capture handler
    pcap_t *get_udp_sniffer() {
        //https://linux.die.net/man/3/pcap_open_live
        //https://www.tcpdump.org/pcap.html

        //http://man7.org/linux/man-pages/man3/pcap_lookupnet.3pcap.html

        char err_buf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 maskp;
        bpf_u_int32 netp;

        if (pcap_lookupnet(interface_name.c_str(), &netp, &maskp, err_buf) != 0) {
            string msg = "Function pcap_lookupnet() failed with msg: ";
            msg.insert(msg.size(), err_buf);
            exit_scanner(INTERN_ERR, msg);
        }

        pcap_t *handler;
        handler = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, 500, err_buf);

        if (handler == nullptr) {
            string msg = "Function pcap_open_live(), failed with msg: ";
            msg.insert(msg.size(), err_buf);
            exit_scanner(INTERN_ERR, msg);
        }

        //hhttps://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Destination_unreachable
        //https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6

        string filter_contend;
        bpf_program filter{};

        if (ip_type == AF_INET) {
            filter_contend =
                    "icmp[icmptype]==icmp-unreach and icmp[icmpcode]==3 and src " + target_IP;
        } else {
            filter_contend = "icmp6 and ip6[40]==1 and src " + target_IP;
        }


        if (pcap_compile(handler, &filter, filter_contend.c_str(), 0, maskp) != 0) {
            pcap_close(handler);
            string msg = "Function pcap_compile() failed with msg: ";
            msg.append(pcap_geterr(handler));
            exit_scanner(INTERN_ERR, msg);
        }

        if (pcap_setfilter(handler, &filter) != 0) {
            pcap_close(handler);
            exit_scanner(INTERN_ERR, "Function pcap_setfilter() failed.");
        }

        return handler;
    }


    int get_upd_socket() {
        int s_socket;
        s_socket = socket(ip_type, SOCK_DGRAM, 0);
        if (s_socket == -1) {
            clear_and_exit(INTERN_ERR, "Function socket() failed.");
        }

        // add interface_name
        //https://stackoverflow.com/questions/3998569/how-to-bind-raw-socket-to-specific-interface
        if (setsockopt(s_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name.c_str(), strlen(interface_name.c_str())) <
            0) {
            clear_and_exit(INTERN_ERR, "Function setsockopt() failed.");
        }

        //reusable
        int enable = 1;
        if (setsockopt(s_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            string msg = "Function setsockopt() failed.";
            clear_and_exit(INTERN_ERR, msg);
        }

        return s_socket;
    }


    void send_upd_package(int s_socket, int port) {
        int res;
        char c_msg[] = "hello";

        if (ip_type == AF_INET) {
            //https://www.gta.ufrj.br/ensino/eel878/sockets/sockaddr_inman.html
            struct sockaddr_in server_address{};
            server_address.sin_family = ip_type;
            server_address.sin_port = htons(port);
            inet_pton(ip_type, target_IP.c_str(), &server_address.sin_addr.s_addr);

            res = sendto(s_socket, c_msg, strlen(c_msg) + 1, 0, (sockaddr *) &server_address, sizeof(server_address));

        } else {
            struct sockaddr_in6 server_address{};
            server_address.sin6_family = ip_type;
            server_address.sin6_port = htons(port);

            inet_pton(ip_type, target_IP.c_str(), &server_address.sin6_addr);

            res = sendto(s_socket, c_msg, strlen(c_msg) + 1, 0, (sockaddr *) &server_address, sizeof(server_address));
        }

        if (res < 0) {
            perror("sendto");
            clear_and_exit(INTERN_ERR, "Function sendto() failed.");
        }
    }

// pcap_dispatch ipv6 callback
    void icmpv6_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        results[current_port] = true;
    }

// pcap_dispatch ipv4 callback
    void icmp_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        // https://www.devdungeon.com/content/using-libpcap-c

        const u_char *ip_header;
        const u_char *icmp_header;
        const u_char *inner_ip_header;
        const u_char *payload;

        int ethernet_header_length = 14;
        int ip_header_length;
        int inner_ip_length = 20; // its my header, always 20

        if (ip_type != AF_INET) {
            return;
        }

        //Ethernet header
        struct ether_header *eth_header;
        eth_header = (struct ether_header *) packet;
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return;
        }

        // Ip header
        ip_header = packet + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F);
        ip_header_length = ip_header_length * 4;
        u_char protocol = *(ip_header + 9);

        if (protocol != IPPROTO_ICMP) {
            return;
        }

        icmp_header = packet + ethernet_header_length + ip_header_length;
        inner_ip_header = icmp_header + 8;

        payload = inner_ip_header + inner_ip_length - 2;

        // get dst port
        unsigned short *dst_port;
        dst_port = (unsigned short *) payload + 2;

        unsigned short dst_port_num = ntohs(*dst_port);
        results[dst_port_num] = true;

    }

    void send_package_with_break(pcap_t *handler, int s_socket, int port) {
        send_upd_package(s_socket, port);
        sleep(1);
        pcap_breakloop(handler);
    }

    void send_all_packages(pcap_t *handler) {
        vector<thread> threads_vec(ports.size());
        int s_socket = get_upd_socket();

        // first round
        for (u_int i = 0; i < ports.size(); i++) {
            results[i] = false;
            threads_vec.at(i) = thread(send_upd_package, s_socket, ports.at(i));
        }
        for (auto &t: threads_vec) {
            t.join();
        }
        sleep(1);

        vector<int> repead_ports;
        for (auto &port: ports) {
            if (!results[port]) {
                repead_ports.push_back(port);
            }
        }

        // second round
        if (repead_ports.size() > 0) {
            vector<thread> threads_vec_rep(repead_ports.size());
            for (unsigned int i = 0; i < repead_ports.size(); i++) {
                threads_vec_rep.at(i) = thread(send_upd_package, s_socket, repead_ports.at(i));
            }

            for (auto &t: threads_vec_rep) {
                t.join();
            }
            sleep(1);
        }

        pcap_breakloop(handler);
        close(s_socket);
    }

    void scan_ipv4() {
        char err_buf[PCAP_ERRBUF_SIZE];
        pcap_t *handler = get_udp_sniffer();
        pcap_setnonblock(handler, 1, err_buf);

        thread port_scanning(send_all_packages, handler);

        pcap_dispatch(handler, 0, icmp_handler, nullptr);

        port_scanning.join();
        pcap_close(handler);
    }

    void scan_ipv6() {
        pcap_t *handler = get_udp_sniffer();
        int s_socket = get_upd_socket();

        char err_buf[PCAP_ERRBUF_SIZE];

        for (auto &port:ports) {
            current_port = port;
            thread package_sending(send_package_with_break, handler, s_socket, port);

            pcap_setnonblock(handler, 1, err_buf);
            pcap_dispatch(handler, 0, icmpv6_handler, nullptr);
            package_sending.join();
        }

        close(s_socket);
        pcap_close(handler);

    }
    void print_results() {

        for (auto &port: ports) {
            if (results[port]) {
                printf("udp\t%d\tclosed\n", port);
            } else {
                printf("udp\t%d\topened\n", port);
            }
        }

        cout << "\n";
    }

    void scan_udp(string interface_name_a, string target_IP_a, vector<int> ports_a, int ip_type_a) {
        if (ports_a.empty()) return;

        target_IP = target_IP_a;
        interface_name = interface_name_a;
        ports = ports_a;
        ip_type = ip_type_a;

        if (ip_type == AF_INET)
            scan_ipv4();
        else
            scan_ipv6();

        print_results();
    }

    void clear_and_exit(scanner_return_code err_code, string msg) {
        exit_scanner(err_code, msg);
    }
}
