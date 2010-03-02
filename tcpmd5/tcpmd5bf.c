/*
 *      tcpmd5bf.c
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

#include <Python.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>

#ifndef ARCH_IS_BIG_ENDIAN
#define ARCH_IS_BIG_ENDIAN 0
#endif
#include "lib/md5.h"

#define VERSION "0.1.4"
#define MAX_BRUTE_PW_LEN 16
#define CHECK_FOR_LOCKFILE 100000

struct tcp4_pseudohdr {
	__uint32_t		saddr;
	__uint32_t		daddr;
	__uint8_t		pad;
	__uint8_t		protocol;
	__uint16_t 		len;
};

int inc_brute_pw_r(char *cur, int pos) {
    if(cur[pos] == 0) {
        cur[pos] = 33;
        return 1;
    }
    else if(cur[pos] >= 33 && cur[pos] < 126) {
        cur[pos]++;
        return 1;
    }
    else {
        cur[pos] = 33;
        if(pos < MAX_BRUTE_PW_LEN)
            return inc_brute_pw_r(cur, pos+1);
        else
            return 0;
    }
}

int inc_brute_pw(char *cur, int pos, int full) {
    if(full)
        return inc_brute_pw_r(cur, pos);

    if(cur[pos] == 0) {
        cur[pos] = 48;
        return 1;
    }
    else if(cur[pos] >= 48 && cur[pos] < 57) {
        cur[pos]++;
        return 1;
    }
    else if(cur[pos] == 57) {
        cur[pos] = 65;
        return 1;
    }
    else if(cur[pos] >= 57 && cur[pos] < 90) {
        cur[pos]++;
        return 1;
    }
    else if(cur[pos] == 90) {
        cur[pos] = 97;
        return 1;
    }
    else if(cur[pos] >= 97 && cur[pos] < 122) {
        cur[pos]++;
        return 1;
    }
    else {
        cur[pos] = 48;
        if(pos < MAX_BRUTE_PW_LEN)
            return inc_brute_pw(cur, pos+1, full);
        else
            return 0;
    }
}

void pre_calc_md5(const u_char *packet, int len, md5_state_t *state) {
    struct ip ip;
    struct tcphdr tcp;
    struct tcp4_pseudohdr phdr;

    memcpy(&ip, packet, sizeof(struct ip));
    memcpy(&tcp, packet + sizeof(struct ip), sizeof(struct tcphdr));

    phdr.saddr = ip.ip_src.s_addr;
    phdr.daddr = ip.ip_dst.s_addr;
    phdr.pad = 0;
    phdr.protocol = IPPROTO_TCP;
    phdr.len = htons(len - sizeof(struct ip));

    md5_init(state);

//1. the TCP pseudo-header (in the order: source IP address,
//   destination IP address, zero-padded protocol number, and
//   segment length)
    md5_append(state, (const md5_byte_t *) &phdr, sizeof(struct tcp4_pseudohdr));

//2. the TCP header, excluding options, and assuming a checksum of
//   zero
    tcp.th_sum = 0;
    md5_append(state, (const md5_byte_t *) &tcp, sizeof(struct tcphdr));
    
//3. the TCP segment data (if any)
    unsigned head_len = sizeof(struct ip) + (tcp.th_off << 2);
    unsigned data_len = len > head_len ? len - head_len : 0;
    md5_append(state, (const md5_byte_t *) packet + head_len, data_len);
}

static PyObject *
tcpmd5bf_bf(PyObject *self, PyObject *args)
{
    int bf, full, len;
    const char *wl, *data;
    FILE *wlist;
    char brute_pw[MAX_BRUTE_PW_LEN];
    char line[512];
    char *pw = NULL;
    char *md5sum;
    md5_byte_t digest[16];
    md5_state_t state, cur;
    int count = 0;
    char *lockfile;
    struct stat fcheck;

    if(!PyArg_ParseTuple(args, "iisss#s", &bf, &full, &wl, &md5sum, &data, &len, &lockfile))
        return NULL;

    pre_calc_md5((u_char *) data, len, &state);

    if(!bf) {
        if(!(wlist = fopen(wl, "r"))) {
            fprintf(stderr, "Cant open wordlist: %s\n", strerror(errno));
            return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
            
        while(fgets(line, 512, wlist)) {
            if(count % CHECK_FOR_LOCKFILE == 0) {
                if(stat(lockfile, &fcheck))
                    break;
                count = 0;
            }
            char *tmp = strchr(line, '\n');
            if(tmp)
                *tmp = '\0';
            tmp = strchr(line, '\r');
            if(tmp)
                *tmp = '\0';
            memcpy(&cur, &state, sizeof(md5_state_t));
            md5_append(&cur, (const md5_byte_t *) line, strlen(line));
            md5_finish(&cur, digest);
            if(!memcmp(md5sum, digest, 16)) {
                pw = line;
                break;
            }
            count++;
        }

        Py_END_ALLOW_THREADS
    }
    else {
        bzero(brute_pw, MAX_BRUTE_PW_LEN);

        Py_BEGIN_ALLOW_THREADS

        do {
            if(count % CHECK_FOR_LOCKFILE == 0) {
                if(stat(lockfile, &fcheck))
                    break;
                count = 0;
            }
            memcpy(&cur, &state, sizeof(md5_state_t));
            md5_append(&cur, (const md5_byte_t *) brute_pw, strlen(brute_pw));
            md5_finish(&cur, digest);
            if(!memcmp(md5sum, digest, 16)) {
                pw = brute_pw;
                break;
            }
            count++;
        } while(inc_brute_pw(brute_pw, 0, full));
        
        Py_END_ALLOW_THREADS
    }

    return Py_BuildValue("s", pw);
}

static PyMethodDef Tcpmd5bfMethods[] = {
    {"bf", tcpmd5bf_bf, METH_VARARGS, "Bruteforce cacking of tcpmd5 auth"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
inittcpmd5bf(void)
{
    PyObject *m;

    m = Py_InitModule("tcpmd5bf", Tcpmd5bfMethods);
    if (m == NULL)
        return;
}
