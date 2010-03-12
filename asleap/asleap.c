/*
 *      asleap.c
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

#include <stdio.h>
#include <string.h>

#include "lib/asleap/asleap.h"
#include "lib/asleap/sha1.h"

extern int attack_leap(struct asleap_data *asleap);

static PyObject *
atk_leap(PyObject *self, PyObject *args)
{
    struct asleap_data data;
    int chall_len, resp_len, id, user_len;
    char *wl, *challenge, *response, *user;

    if(!PyArg_ParseTuple(args, "ss#s#is#", &wl, &challenge, &chall_len, &response, &resp_len, &id, &user, &user_len))
        return NULL;
    
    bzero(&data, sizeof(struct asleap_data));
    if(chall_len != 8) {
        fprintf(stderr, "Challange len != 8\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    memcpy(data.challenge, challenge, 8);

    if(resp_len != 24) {
        fprintf(stderr, "Response len != 24\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    memcpy(data.response, response, 24);
    data.eapid = id;

    if(!user_len || user_len > 256)  {
        fprintf(stderr, "Username len invalid\n");
        Py_INCREF(Py_None);
        return Py_None;
    }
    strncpy(data.username, user, 256);

    data.verbose = 0;
    strncpy(data.wordfile, wl, 255);

    data.leapchalfound = 1;
	data.leaprespfound = 1;
    data.manualchalresp = 1;

    attack_leap(&data);

    return Py_BuildValue("s", data.password);
}

/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 */

void sha1_vector(size_t num_elem, const unsigned char *addr[], const size_t *len,
		 unsigned char *mac)
{
	SHA1_CTX ctx;
	size_t i;

	SHA1Init(&ctx);
	for (i = 0; i < num_elem; i++) 
		SHA1Update(&ctx, addr[i], len[i]);
	
	SHA1Final(mac, &ctx);
}

/**
 * hmac_sha1_vector - HMAC-SHA1 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (20 bytes)
 */

void hmac_sha1_vector(const unsigned char *key, size_t key_len, size_t num_elem,
		      const unsigned char *addr[], const size_t *len, unsigned char *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[20];
	const unsigned char *_addr[6];
	size_t _len[6], i;

	if (num_elem > 5) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return;
	}

        /* if key is longer than 64 bytes reset it to key = SHA1(key) */
       if (key_len > 64) {
		sha1_vector(1, &key, &key_len, tk);
		key = tk;
		key_len = 20;
        }

	/* the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	sha1_vector(1 + num_elem, _addr, _len, mac);

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA1_MAC_LEN;
	sha1_vector(2, _addr, _len, mac);
}

/**
 * sha1_prf - SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1)
 * @key: Key for PRF
 * @key_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @data: Extra data to bind into the key
 * @data_len: Length of the data
 * @buf: Buffer for the generated pseudo-random key
 * @buf_len: Number of bytes of key to generate
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key (e.g., PMK in IEEE 802.11i).
 */
void sha1_prf(const unsigned char *key, size_t key_len, const char *label, const unsigned char *data, size_t data_len, unsigned char *buf, size_t buf_len) {
    unsigned char counter = 0;
    size_t pos, plen;
    unsigned char hash[SHA1_MAC_LEN];
    size_t label_len = strlen(label) + 1;
    const unsigned char *addr[3];
    size_t len[3];

    addr[0] = (unsigned char *) label;
    len[0] = label_len;
    addr[1] = data;
    len[1] = data_len;
    addr[2] = &counter;
    len[2] = 1;

    pos = 0;
    while (pos < buf_len) {
        plen = buf_len - pos;
        if (plen >= SHA1_MAC_LEN) {
            hmac_sha1_vector(key, key_len, 3, addr, len,
                     &buf[pos]);
            pos += SHA1_MAC_LEN;
        } else {
            hmac_sha1_vector(key, key_len, 3, addr, len,
                     hash);
            memcpy(&buf[pos], hash, plen);
            break;
        }
        counter++;
    }
}
    
static PyObject *
sha1_prf_func(PyObject *self, PyObject *args)
{
    unsigned char *key, *data;
    char *label;
    unsigned int key_len, data_len, len;
    unsigned char buf[1024];
    
    if(!PyArg_ParseTuple(args, "s#ss#i", &key, &key_len, &label, &data, &data_len, &len))
        return NULL;

    sha1_prf(key, key_len, label, data, data_len, buf, len);
    
    return Py_BuildValue("s#", buf, len);
}

static PyMethodDef AsleapMethods[] = {
    {"attack_leap", atk_leap, METH_VARARGS, "Bruteforce cacking of asleap"},
    {"sha1_prf", sha1_prf_func, METH_VARARGS, "Gen SHA1-PRF"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initasleap(void)
{
    PyObject *m;

    m = Py_InitModule("asleap", AsleapMethods);
    if (m == NULL)
        return;
}
