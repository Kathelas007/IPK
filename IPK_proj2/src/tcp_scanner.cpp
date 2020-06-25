/**
 * author: Muskova Katerina (xmusko00)
 * file: tcp_scanner.cpp
 */

#include "tcp_scanner.h"
#include "scan_exit.h"

#include "string"
#include "vector"
#include "cstring"
#include "map"

#include <unistd.h>
#include <sys/socket.h>

#include <pcap/pcap.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include<netdb.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<netinet/ip6.h>

#include <thread>
#include <mutex>

namespace TCP {

    string interface_IP;
    string interface_name;
    string target_IP;
    vector<int> ports;
    int ip_type;

    map<int, port_state> results;
    mutex results_mutex;

    void clear_and_exit(scanner_return_code err_code, string msg) {
        exit_scanner(err_code, msg);
    }


    int get_port_from_packet(const struct pcap_pkthdr *header, const u_char *packet) {
        // https://www.devdungeon.com/content/using-libpcap-c

        const u_char *ip_header;
        const u_char *tcp_header;

        int ethernet_header_length = 14;
        int ip_header_length;
        int tcp_header_length;

        //Ethernet header
        struct ether_header *eth_header;
        eth_header = (struct ether_header *) packet;
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return -1;
        }

        // Ip header
        ip_header = packet + ethernet_header_length;
        ip_header_length = ((*ip_header) & 0x0F);
        ip_header_length = ip_header_length * 4;
        u_char protocol = *(ip_header + 9);

        if (protocol != IPPROTO_TCP) {
            cout << "not TCP";
            return -1;
        }

        tcp_header = packet + ethernet_header_length + ip_header_length;
        tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
        tcp_header_length = tcp_header_length * 4;

        if (tcp_header_length < 4) return -1;

        unsigned short *src_port;
        src_port = (unsigned short *) tcp_header;

        unsigned short src_port_num = ntohs(*(src_port));
        return src_port_num;
    }


    void ack_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

        int port = get_port_from_packet(header, packet);

        if(port == -1) return;

        results_mutex.lock();
        results[port] = OPENDED;
        results_mutex.unlock();
    }

    void rst_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        int port = get_port_from_packet(header, packet);

        results_mutex.lock();
        results[port] = CLOSED;
        results_mutex.unlock();
    }

    // get pointer to pcap capture handler
    pcap_t *get_tcp_sniffer(filter_type type) {
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
        handler = pcap_open_live(interface_name.c_str(), BUFSIZ, 1, -1, err_buf);

        if (handler == nullptr) {
            string msg = "Function pcap_open_live(), failed with msg: ";
            msg.insert(msg.size(), err_buf);
            exit_scanner(INTERN_ERR, msg);
        }

        string filter_contend;
        bpf_program filter{};

        if (ip_type == AF_INET) {
            if (type == ACK) {
                filter_contend =
                        "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) != 0 and src " + target_IP;
            } else {
                filter_contend =
                        "tcp[tcpflags] & (tcp-rst) != 0 and tcp[tcpflags] & (tcp-ack) != 0 and src " + target_IP;
            }
        } else {
            // todo !!!!!!!!!!!
            if (type == ACK) {
                filter_contend =
                        "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) != 0 and src " + target_IP;
            } else {
                filter_contend =
                        "tcp[tcpflags] & (tcp-rst) != 0 and tcp[tcpflags] & (tcp-ack) != 0 and src " + target_IP;
            }
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

        pcap_setnonblock(handler, 1, err_buf);

        return handler;
    }

    int get_socket() {
        //https://www.schoenitzer.de/blog/2018/Linux%20Raw%20Sockets.html

        int s_socket = socket(ip_type, SOCK_RAW, IPPROTO_TCP);
        if (s_socket == -1) {
            clear_and_exit(INTERN_ERR, "Function socket() failed.");
        }

        // chosen interface
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

        if (setsockopt(s_socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
            string msg = "Function setsockopt() failed.";
            clear_and_exit(INTERN_ERR, msg);
        }


        if (ip_type == AF_INET) {
            if (setsockopt(s_socket, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(int)) < 0) {
                clear_and_exit(INTERN_ERR, "Function setsockopt() failed.");
            }
        } else {
           // IPv6
        }

        return s_socket;
    }

    unsigned short check_sum(unsigned short *ptr, int size) {
        //https://www.binarytides.com/raw-sockets-c-code-linux/

        long sum;
        unsigned short odd_byte;
        short check_sum;

        sum = 0;

        while (size > 1) {
            sum += *ptr++;
            size -= 2;
        }

        if (size == 1) {
            odd_byte = 0;
            *((u_char *) &odd_byte) = *(u_char *) ptr;
            sum += odd_byte;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum = sum + (sum >> 16);
        check_sum = (short) ~sum;

        return (check_sum);
    }

    void send_ipv4_syn_package(int s_socket, int port) {
        //https://www.binarytides.com/raw-sockets-c-code-linux/

        char datagram[4096];
        memset(datagram, 0, 4096);

        iphdr *iph_p = (struct iphdr *) datagram;

        iph_p->saddr = inet_addr(interface_IP.c_str());
        iph_p->daddr = inet_addr(target_IP.c_str());

        iph_p->version = 4;
        iph_p->protocol = IPPROTO_TCP;

        iph_p->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
        iph_p->ihl = 5;
        iph_p->tos = 0;
        iph_p->id = htons(55555);    //random
        iph_p->frag_off = htons(0); // noup
        iph_p->ttl = 128;
        iph_p->check = 0;        // kernel fills

        iph_p->check = check_sum((unsigned short *) datagram, iph_p->tot_len);

        tcphdr *tcph_p = (struct tcphdr *) (datagram + sizeof(struct ip));
        static unsigned long num = 0;
        num++;

        tcph_p->source = htons(555);
        tcph_p->dest = htons(port);
        tcph_p->seq = num;
        tcph_p->ack_seq = 0; // its first one package
        tcph_p->doff = 5; // data begin * 4

        tcph_p->syn = 1; // only, others 0

        tcph_p->window = htons(5840); // max size
        tcph_p->check = 0;

        struct sockaddr_in server_address{};
        server_address.sin_family = ip_type;
        server_address.sin_port = htons(port);
        inet_pton(ip_type, target_IP.c_str(), &server_address.sin_addr.s_addr);

        struct pseudo_header psh_p;
        psh_p.source_address = iph_p->saddr;
        psh_p.dest_address = server_address.sin_addr.s_addr;
        psh_p.placeholder = 0;
        psh_p.protocol = IPPROTO_TCP;
        psh_p.tcp_length = htons(sizeof(struct tcphdr));
        psh_p.tcp = *tcph_p;
        tcph_p->check = 0;

        tcph_p->check = check_sum((unsigned short *) &psh_p, sizeof(struct pseudo_header));


        int res = sendto(s_socket, datagram, sizeof(iphdr) + sizeof(tcphdr), 0, (sockaddr *) &server_address,
                         sizeof(server_address));

        if (res < 0) {
            perror("sendto");
            clear_and_exit(INTERN_ERR, "Function sendto() failed.");
        }
    }

    void send_ipv6_syn_package(int s_socket, int port) {
        // IPv6
    }

    void send_syn_package(int s_socket, int port) {
        if (ip_type == AF_INET) {
            send_ipv4_syn_package(s_socket, port);
        } else {
            send_ipv6_syn_package(s_socket, port);
        }

    }

    void send_all_packages() {
        int s_socket = get_socket();
        for (auto &port: ports) {
            if (results[port] == FILTRED)
                send_syn_package(s_socket, port);
        }
        close(s_socket);

    }

    void start_scan_loop(pcap_t *handler_a, pcap_t *handler_r) {
        thread sl1(pcap_loop, handler_a, 0, ack_handler, nullptr);
        thread sl2(pcap_loop, handler_r, 0, rst_handler, nullptr);

        sleep(2);
        pcap_breakloop(handler_a);
        pcap_breakloop(handler_r);

        sl1.join();
        sl2.join();
    }


    void scan_ports() {
        pcap_t *handler_a = get_tcp_sniffer(ACK);
        pcap_t *handler_r = get_tcp_sniffer(RST);

        //first round
        thread scanning(start_scan_loop, handler_a, handler_r);
        send_all_packages();
        scanning.join();

        // second try
        thread scanning2(start_scan_loop, handler_a, handler_r);
        send_all_packages();
        scanning2.join();

        pcap_close(handler_a);
        pcap_close(handler_r);

    }


    void print_results() {
        for (auto &port: ports) {
            if (results[port] == OPENDED) {
                printf("tcp\t%d\topened\n", port);
            } else if (results[port] == CLOSED) {
                printf("tcp\t%d\tclosed\n", port);
            } else if (results[port] == FILTRED) {
                printf("tcp\t%d\tfiltred\n", port);
            }
        }
    }

    void scan_tcp(string interface_IP_a, string interface_name_a, string target_IP_a,
                  vector<int> ports_a, int ip_type_a) {
        if (ports_a.empty()) return;

        // IPv6 not implemented
        if (ip_type_a == AF_INET6) return;

        interface_IP = interface_IP_a;
        target_IP = target_IP_a;
        interface_name = interface_name_a;
        ports = ports_a;
        ip_type = ip_type_a;

        for (auto &port: ports) {
            results[port] = FILTRED;
        }

        scan_ports();

        print_results();
    }
}