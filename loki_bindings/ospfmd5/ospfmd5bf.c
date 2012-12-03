/*
 *      ospfmd5bf.c
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

#ifdef _WIN32
#include <winsock2.h>
#define bzero(b,len) (memset((b), '\0', (len)), (void) 0)  
#else
#include <arpa/inet.h>
#endif

#ifndef ARCH_IS_BIG_ENDIAN
#define ARCH_IS_BIG_ENDIAN 0
#endif
#include "lib/md5.h"

#define VERSION "0.1"
#define MAX_BRUTE_PW_LEN 16
#define CHECK_FOR_LOCKFILE 100000

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

static PyObject *
ospfmd5bf_bf(PyObject *self, PyObject *args)
{
    int bf, full, len, foo;
    const char *wl, *data;
    FILE *wlist, *lock;
    char brute_pw[MAX_BRUTE_PW_LEN+1];
    char line[512];
    char *pw = NULL;
    char *md5sum;
    int count = 0;
    char *lockfile;
    struct stat fcheck;
    md5_state_t base, cur;
    md5_byte_t digest[16];

    if(!PyArg_ParseTuple(args, "iiss#s#s", &bf, &full, &wl, &md5sum, &foo, &data, &len, &lockfile))
        return NULL;

    md5_init(&base);
    md5_append(&base, (const md5_byte_t *) data, len);

    if(!bf) {
        if(!(wlist = fopen(wl, "r"))) {
            fprintf(stderr, "Cant open wordlist: %s\n", strerror(errno));
            return NULL;
        }

        Py_BEGIN_ALLOW_THREADS
            
        while(fgets(line, 512, wlist)) {
            char *tmp = strchr(line, '\n');
            if(tmp)
                *tmp = '\0';
            tmp = strchr(line, '\r');
            if(tmp)
                *tmp = '\0';
            len = strlen(line);
            bzero(line + len, 16 - len);
            if(count % CHECK_FOR_LOCKFILE == 0) {
                if(stat(lockfile, &fcheck)) {
                    fprintf(stderr, "No lockfile, exiting.\n");
                    break;
                }
                if(!(lock = fopen(lockfile, "w"))) {
                    fprintf(stderr, "Cant open lockfile: %s\n", strerror(errno));
                    return NULL;
                }
                fprintf(lock, "%s", line);
                fclose(lock);
                count = 0;
            }
            memcpy(&cur, &base, sizeof(md5_state_t));
            md5_append(&cur, (const md5_byte_t *) line, 16);
            md5_finish(&cur, digest);
            if(!memcmp(md5sum, digest, 16)) {
                pw = line;
                fprintf(stderr, "Found pw '%s' ('%s' == '%s').\n", pw, md5sum, digest);
                break;
            }
            count++;
        }

        Py_END_ALLOW_THREADS
    }
    else {
        bzero(brute_pw, MAX_BRUTE_PW_LEN+1);

        Py_BEGIN_ALLOW_THREADS

        do {
            if(count % CHECK_FOR_LOCKFILE == 0) {
                if(stat(lockfile, &fcheck)) {
                    fprintf(stderr, "No lockfile, exiting.\n");
                    break;
                }
                if(!(lock = fopen(lockfile, "w"))) {
                    fprintf(stderr, "Cant open lockfile: %s\n", strerror(errno));
                    return NULL;
                }
                fprintf(lock, "%s", brute_pw);
                fclose(lock);
                count = 0;
            }
            memcpy(&cur, &base, sizeof(md5_state_t));
            md5_append(&cur, (const md5_byte_t *) brute_pw, 16);
            md5_finish(&cur, digest);
            if(!memcmp(md5sum, digest, 16)) {
                pw = brute_pw;
                fprintf(stderr, "Found pw '%s' ('%s' == '%s').\n", pw, md5sum, digest);
                break;
            }
            count++;
        } while(inc_brute_pw(brute_pw, 0, full));
        
        Py_END_ALLOW_THREADS
    }

    return Py_BuildValue("s", pw);
}

static PyMethodDef Ospfmd5bfMethods[] = {
    {"bf", ospfmd5bf_bf, METH_VARARGS, "Bruteforce cracking of ospfmd5 auth"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initospfmd5bf(void)
{
    PyObject *m;

    m = Py_InitModule("ospfmd5bf", Ospfmd5bfMethods);
    if (m == NULL)
        return;
}
