/*
 *      mpls-tunnel.c
 *
 *      Copyright 2010 Daniel Mende <dmende@ernw.de>
 */


/*
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of the  nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <dnet.h>
#include <pcap.h>

#define READ_BUFFER_SIZE 1600
#define WRITE_BUFFER_SIZE 1600
#define PCAP_FILTER_SIZE 1024
#define TUN_DEV_NAME_LENGTH 8

#define max(a,b) ((a)>(b) ? (a):(b))
#define min(a,b) ((a)>(b) ? (b):(a))
#define abs(a) ((a)<0 ? ((a)*-1):(a))

eth_t *dnet_handle;
pcap_t *pcap_handle;
int tun_fd;
int run = 1;

long read_label(void *pos, int *exp, int* bos, int* ttl) {
    long label = ntohl(*((unsigned *) pos) & htonl(0xfffff000)) >> 12;
    if (exp)
        *exp = ntohs(*((unsigned *) pos) & htonl(0x00000e00)) >> 9;
    if (bos)
        *bos = ntohs(*((unsigned *) pos) & htonl(0x00000100)) >> 8;
    if (ttl)
        *ttl = ntohs(*((unsigned *) pos) & htonl(0x000000ff));
    return label;
}

void write_label(void *pos, long label, int exp, int bos, int ttl) {
    *((unsigned *) pos) |= htonl(label << 12);
    *((unsigned *) pos) |= htonl(exp << 9 & 0x00000e00);
    *((unsigned *) pos) |= htonl(bos << 8 & 0x00000100);
    *((unsigned *) pos) |= htonl(ttl & 0x000000ff);
}

void sigint(int sig) {
    run = 0;
    close(tun_fd);
    pcap_close(pcap_handle);
    eth_close(dnet_handle);
    exit(0);
}

int tun_alloc(char *dev, short flags) {
    struct ifreq ifr;
    int fd, err;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
        return -1;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags | IFF_NO_PI;
    if( *dev )
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         return err;
    }
    strncpy(dev, ifr.ifr_name, TUN_DEV_NAME_LENGTH);
    return fd;
}

int main(int argc, char *argv[])
{
    int opt;
    unsigned char in[READ_BUFFER_SIZE];
    unsigned char out[WRITE_BUFFER_SIZE];
    int pcap_fd,l,fm;
    fd_set fds;

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pcap_packet;
    char filter[PCAP_FILTER_SIZE];
    struct pcap_pkthdr *pcap_header;
    struct bpf_program pcap_filter;
    
    int verbose = 0;
    char *mode = NULL;
    char *in_device = NULL;
    char *out_device = NULL;
    char *in_label = NULL;
    char *out_label = NULL;
    char *in_mac = NULL;
    char *out_mac = NULL;
    char *in_trans = NULL;
    char *out_trans = NULL;
    char tun_in_device[TUN_DEV_NAME_LENGTH];

    printf("mpls_tun version %s\tby Daniel Mende - dmende@ernw.de\n", VERSION);
    fflush(stdout);
    
    while ((opt = getopt(argc, argv, "vm:d:D:i:o:I:O:ht:T:")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'm':
            mode = optarg;
            break;
        case 'd':
            in_device = optarg;
            break;
        case 'D':
            out_device = optarg;
            break;
        case 'i':
            in_label = optarg;
            break;
        case 'o':
            out_label = optarg;
            break;
        case 'I':
            in_mac = optarg;
            break;
        case 'O':
            out_mac = optarg;
            break;
        case 't':
            in_trans = optarg;
            break;
        case 'T':
            out_trans = optarg;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: %s [-v] -m mode -d in_device -D out_device -i in_label -o out_label -I in_mac -O out_mac [-t in_trans] [-T out_trans]\n\n", argv[0]);
            fprintf(stderr, "-v\t\t: Be verbose\n");
            fprintf(stderr, "-m\t\t: Mode: l3vpn eompls\n");
            fprintf(stderr, "-d in_device\t: in_device for tunnel data\n");
            fprintf(stderr, "-D out_device\t: out_device for tunnel data\n");
            fprintf(stderr, "-i in_label\t: Label of incomming traffic\n");
            fprintf(stderr, "-o out_label\t: Label of outgoing traffic\n");
            fprintf(stderr, "-I in_mac\t: Incomming MAC address\n");
            fprintf(stderr, "-O out_mac\t: Outgoing MAC address\n");
            fprintf(stderr, "-t in_label\t: Transport label of incomming traffic\n");
            fprintf(stderr, "-T out_label\t: Transport label of outgoing traffic\n");
            return 2;
        }
    }

    if(!mode) {
        fprintf(stderr, "No mode selected\n");
        return 2;
    }
    if(!(strcmp(mode, "l3vpn") || strcmp(mode, "eompls"))) {
        fprintf(stderr, "Unknown mode: %s\n", mode);
        return 2;
    }
    if(!in_mac) {
        fprintf(stderr, "No incoming MAC given\n");
        return 2;
    }
    if(!out_mac) {
        fprintf(stderr, "No outgoing MAC given\n");
        return 2;
    }
    if(!in_device) {
        fprintf(stderr, "No in_device for capturing given\n");
        return 2;
    }
    if(!out_device) {
        fprintf(stderr, "No out_device for injection given\n");
        return 2;
    }
    if(!in_label) {
        fprintf(stderr, "No incomming label given\n");
        return 2;
    }
    if(!out_label) {
        fprintf(stderr, "No outgoing label given\n");
        return 2;
    }

    signal(SIGINT, sigint);

    if (!strcmp(mode, "l3vpn")) {
        strncpy(tun_in_device, "tun%d", TUN_DEV_NAME_LENGTH);
        tun_fd = tun_alloc(tun_in_device, IFF_TUN);
        ioctl(tun_fd, TUNSETNOCSUM, 1);
    } else {
        strncpy(tun_in_device, "tap%d", TUN_DEV_NAME_LENGTH);
        tun_fd = tun_alloc(tun_in_device, IFF_TAP);
    }
    if (tun_fd < 0) {
        fprintf(stderr, "Couldnt't open tun in_device: %s\n", tun_in_device);
        return 2;
    }
    if (verbose)
        printf("Tunnel interface %s started\n", tun_in_device);

    pcap_handle = pcap_open_live(in_device, BUFSIZ, 1, 1000, pcap_errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open pcap in_device: %s\n", pcap_errbuf);
        return 2;
    }
    if (verbose) 
        printf("Opening tunnel at %s with MAC %s\n", in_device, in_mac);
        
    snprintf(filter, PCAP_FILTER_SIZE, "ether dst %s", in_mac);
    if (pcap_compile(pcap_handle, &pcap_filter, filter, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    if (pcap_setfilter(pcap_handle, &pcap_filter) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(pcap_handle));
        return 2;
    }
    pcap_fd = pcap_get_selectable_fd(pcap_handle);
    if (pcap_fd < 0) {
        fprintf(stderr, "Unable to get a selectable fd from pcap in_device\n");
        return 2;
    }

    dnet_handle = eth_open(out_device);
    if (dnet_handle == NULL) {
        fprintf(stderr, "Couldn't open in_device: %s\n", out_device);
        return 2;
    }
    if (verbose)
        printf("Sending to MAC %s on interface %s\n", out_mac, out_device);

    fm = max(tun_fd, pcap_fd) + 1;

    while (run)
    {
        struct ether_header *eheader;
        unsigned char *start;

        fflush(stdout);
        FD_ZERO(&fds);
        FD_SET(tun_fd, &fds);
        FD_SET(pcap_fd, &fds);

        select(fm, &fds, NULL, NULL, NULL);
        bzero(out, WRITE_BUFFER_SIZE);
        
        if( FD_ISSET(tun_fd, &fds) ) {      //IN on TUN
            l = read(tun_fd, in, READ_BUFFER_SIZE);
            start = out;

            eheader = (struct ether_header *) start;
            memcpy(eheader->ether_dhost, ether_aton(out_mac)->ether_addr_octet, ETH_ALEN);
            memcpy(eheader->ether_shost, ether_aton(in_mac)->ether_addr_octet, ETH_ALEN);
            eheader->ether_type = htons(0x8847);
            start += sizeof(struct ether_header);
            l += sizeof(struct ether_header);
        
            if(out_trans) {
                write_label(start, atoi(out_trans), 0, 0, 255);
                start += 4;
                l += 4;
            }
            
            //if(!strcmp(mode, "l3vpn")) {
                write_label(start, atoi(out_label), 0, 1, 255);
                start += 4;
                l += 4;

                memcpy(start, in, WRITE_BUFFER_SIZE - abs(out - start)); // LEN ?
            /*} else {
                //
                //
                //
            }*/

            if (eth_send(dnet_handle, (u_char *) out, l) < 0) {
                fprintf(stderr, "Couldn't write packet\n");
                return 2;
            }
        }
        if( FD_ISSET(pcap_fd, &fds) ) {      //IN on PCAP
            if(pcap_next_ex(pcap_handle, &pcap_header, &pcap_packet) > 0) {
                l = pcap_header->len;
                memcpy(in, pcap_packet, min(READ_BUFFER_SIZE, l));
                start = in;

                eheader = (struct ether_header *) start;
                if(eheader->ether_type != htons(0x8847))
                    continue;
                start += sizeof(struct ether_header);
                if(in_trans) {
                    if (read_label(start, NULL, NULL, NULL) != atoi(in_trans))
                        continue;
                    start += 4;
                    l -= 4;
                }
                
                //if(!strcmp(mode, "l3vpn")) {
                    if (read_label(start, NULL, NULL, NULL) != atoi(in_label))
                        continue;
                    start += 4;
                    l -= 4;

                    memcpy(out, start, WRITE_BUFFER_SIZE);
                /*} else {
                    //
                    //
                    //
                }*/

                write(tun_fd, out, l);
            } else {
                fprintf(stderr, "Error on reading from pcap interface\n");
                run = 0;
            }
        }
   }

   close(tun_fd);
   pcap_close(pcap_handle);
   eth_close(dnet_handle);
   
   return 0;
}
