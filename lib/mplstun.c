/*
 *      mplstun.c
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

#include "lib/mplstun.h"

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

int tun_alloc(char *dev, short flags) {
#ifdef USE_LINUX_TUN
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
#endif
}

int mplstun(tun_mode mode, char *in_device, char *out_device, uint16_t in_label, uint16_t out_label, char *in_mac, char *out_mac, uint16_t in_trans_label, uint16_t out_trans_label, char *lock_file)
{
    eth_t *dnet_handle;
    pcap_t *pcap_handle;
    int tun_fd;

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
    char tun_device[TUN_DEV_NAME_LENGTH];
    
    struct ether_header *eheader;
    unsigned char *start;
    int run, ret;
    struct stat fcheck;
    struct timeval timeout;

    if(mode < L2_TUN || mode > L3_TUN) {
        fprintf(stderr, "Unknown mode: %i\n", mode);
        return 2;
    }

    if (mode == L3_TUN) {
        strncpy(tun_device, "tun%d", TUN_DEV_NAME_LENGTH);
        tun_fd = tun_alloc(tun_device, IFF_TUN);
        ioctl(tun_fd, TUNSETNOCSUM, 1);
    } else {
        strncpy(tun_device, "tap%d", TUN_DEV_NAME_LENGTH);
        tun_fd = tun_alloc(tun_device, IFF_TAP);
    }
    if (tun_fd < 0) {
        fprintf(stderr, "Couldnt't create tunnel device: %s\n", tun_device);
        return 2;
    }
    if (verbose)
        printf("Tunnel interface %s created\n", tun_device);

    pcap_handle = pcap_open_live(in_device, BUFSIZ, 1, 1000, pcap_errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't open pcap in_device: %s\n", pcap_errbuf);
        return 2;
    }
    if (verbose) 
        printf("Opening tunnel at %s with MAC %s\n", in_device, in_mac);
        
    snprintf(filter, PCAP_FILTER_SIZE, "ether dst %s and ether type 0x8847", in_mac);
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
        fprintf(stderr, "Couldn't open out_device: %s\n", out_device);
        return 2;
    }
    if (verbose)
        printf("Sending to MAC %s on interface %s\n", out_mac, out_device);

    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = TIMEOUT_USEC;

    fm = max(tun_fd, pcap_fd) + 1;
    FD_ZERO(&fds);
    FD_SET(tun_fd, &fds);
    FD_SET(pcap_fd, &fds);

    for(run = 1; run; run++)
    {
        ret = select(fm, &fds, NULL, NULL, &timeout);
        bzero(out, WRITE_BUFFER_SIZE);

        if (run % CHECK_FOR_LOCKFILE || !ret) {
            if(stat(lock_file, &fcheck))
                break;
            run = 1;
        }
        
        if( FD_ISSET(tun_fd, &fds) ) {      //IN on TUN
            l = read(tun_fd, in, READ_BUFFER_SIZE);
            start = out;

            eheader = (struct ether_header *) start;
            memcpy(eheader->ether_dhost, ether_aton(out_mac)->ether_addr_octet, ETH_ALEN);
            memcpy(eheader->ether_shost, ether_aton(in_mac)->ether_addr_octet, ETH_ALEN);
            eheader->ether_type = htons(0x8847);
            start += sizeof(struct ether_header);
            l += sizeof(struct ether_header);
        
            if(out_trans_label) {
                write_label(start, out_trans_label, 0, 0, 255);
                start += 4;
                l += 4;
            }
            
            //if(!strcmp(mode, "l3vpn")) {
                write_label(start, out_label, 0, 1, 255);
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
                //if(eheader->ether_type != htons(0x8847))
                //    continue;
                start += sizeof(struct ether_header);
                if(in_trans_label) {
                    if (read_label(start, NULL, NULL, NULL) != in_trans_label)
                        continue;
                    start += 4;
                    l -= 4;
                }
                
                //if(!strcmp(mode, "l3vpn")) {
                    if (read_label(start, NULL, NULL, NULL) != in_label)
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
                return 2;
            }
        }
   }

   close(tun_fd);
   pcap_close(pcap_handle);
   eth_close(dnet_handle);
   
   return 0;
}