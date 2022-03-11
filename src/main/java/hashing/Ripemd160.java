package hashing;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

// Copyrights
// ==========

// This code is a derived from an implementation by Markus Friedl which is
// subject to the following license. This Python implementation is not
// subject to any other license.

/*
* Copyright (c) 2001 Markus Friedl.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES LOSS OF USE,
* DATA, OR PROFITS OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*
* Preneel, Bosselaers, Dobbertin, "The Cryptographic Hash Function RIPEMD-160",
* RSA Laboratories, CryptoBytes, Volume 3, Number 2, Autumn 1997,
* ftp://ftp.rsasecurity.com/pub/cryptobytes/crypto3n2.pdf
*/
class RMDContext{
    long[] state;
    BigInteger count;
    byte[] buffer;

    RMDContext(){
        state = new long[] {0x67452301L, 0xEFCDAB89L, 0x98BADCFEL, 0x10325476L, 0xC3D2E1F0L};
        count = BigInteger.ZERO;
        buffer = new byte[64];
    }
    
}

class transforms {
    private long K0, K1, K2, K3, K4, KK0, KK1, KK2, KK3, KK4;

    transforms(){
        K0 = 0x00000000L;
        K1 = 0x5A827999L;
        K2 = 0x6ED9EBA1L;
        K3 = 0x8F1BBCDCL;
        K4 = 0xA953FD4EL;
        KK0 = 0x50A28BE6L;
        KK1 = 0x5C4DD124L;
        KK2 = 0x6D703EF3L;
        KK3 = 0x7A6D76E9L;
        KK4 = 0x00000000L;
    }
    
    private long ROL(long n, long x){
        return ((x << n) & 0xffffffffL | (x >> (32 - n)));
    }
    private long F0(long x, long y, long z){
        return x ^ y ^ z;
    }
    // modulo fix replace n % m by (((n % m) + m) % m) 
    private long F1(long x, long y, long z){
        return (x & y) | ((((((~x) % 0x100000000L)) + 0x100000000L) % 0x100000000L) & z);
    }
    private long F2(long x, long y, long z){
        return ((x | ((((~y) % 0x100000000L) + 0x100000000L) % 0x100000000L)) ^ z);
    }
    private long F3(long x, long y, long z){
        return (x & z) | ((((((~z) % 0x100000000L)) + 0x100000000L) % 0x100000000L) & y);
    }
    private long F4(long x, long y, long z){
        return x ^ (y | (((((~z) % 0x100000000L)) + 0x100000000L) % 0x100000000L));

    }
    private long[] R(long a, long b, long c, long d, long e, int Fj, long Kj, long sj, int rj, long[] X){
        switch(Fj){
            case 0:
                a = ROL(sj, ((((a + F0(b, c, d) + X[rj] + Kj) % 0x100000000L)) + 0x100000000L) % 0x100000000L) + e;
                break;
            case 1:
                a = ROL(sj, ((((a + F1(b, c, d) + X[rj] + Kj) % 0x100000000L)) + 0x100000000L) % 0x100000000L) + e;
                break;
            case 2:
                a = ROL(sj, ((((a + F2(b, c, d) + X[rj] + Kj) % 0x100000000L)) + 0x100000000L) % 0x100000000L) + e;
                break;
            case 3:
                a = ROL(sj, ((((a + F3(b, c, d) + X[rj] + Kj) % 0x100000000L)) + 0x100000000L) % 0x100000000L) + e;
                break;
            case 4:
                a = ROL(sj, ((((a + F4(b, c, d) + X[rj] + Kj) % 0x100000000L)) + 0x100000000L) % 0x100000000L) + e;
                break;
        }
        c = ROL(10, c);
        return (new long[] {(((a % 0x100000000L)) + 0x100000000L) % 0x100000000L,c});
    }
    protected long[] RMDTransform(long[] state, byte[] block){
        long []x = new long[16];
        for (int i = 0;i < 64; i += 4){
            byte []conv = new byte[8];
            conv[7] = block[i];
            conv[6] = block[i + 1];
            conv[5] = block[i + 2];
            conv[4] = block[i + 3];
            x[i/4] = ByteBuffer.wrap(conv).getLong();
        }

        long a = state[0];
        long b = state[1];
        long c = state[2];
        long d = state[3];
        long e = state[4];

        //Round 1
        long []temp;;
        temp = R(a, b, c, d, e, 0, K0, 11,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, K0, 14,  1, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, K0, 15,  2, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, K0, 12,  3, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, K0,  5,  4, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, K0,  8,  5, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, K0,  7,  6, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, K0,  9,  7, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, K0, 11,  8, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, K0, 13,  9, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, K0, 14, 10, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, K0, 15, 11, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, K0,  6, 12, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, K0,  7, 13, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, K0,  9, 14, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, K0,  8, 15, x);
        a = temp[0];
        c = temp[1];
        // Round 2

        temp = R(e, a, b, c, d, 1, K1,  7,  7, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, K1,  6,  4, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, K1,  8, 13, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, K1, 13,  1, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, K1, 11, 10, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, K1,  9,  6, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, K1,  7, 15, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, K1, 15,  3, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, K1,  7, 12, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, K1, 12,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, K1, 15,  9, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, K1,  9,  5, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, K1, 11,  2, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, K1,  7, 14, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, K1, 13, 11, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, K1, 12,  8, x); 
        e = temp[0];
        b = temp[1];
        /* 31 */
    /* Round 3 */
        temp = R(d, e, a, b, c, 2, K2, 11,  3, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 2, K2, 13, 10, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, K2,  6, 14, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, K2,  7,  4, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, K2, 14,  9, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, K2,  9, 15, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 2, K2, 13,  8, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, K2, 15,  1, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, K2, 14,  2, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, K2,  8,  7, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, K2, 13,  0, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 2, K2,  6,  6, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, K2,  5, 13, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, K2, 12, 11, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, K2,  7,  5, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, K2,  5, 12, x); 
        d = temp[0];
        a = temp[1];
        /* 47 */
    /* Round 4 */
        temp =R(c, d, e, a, b, 3, K3, 11,  1, x);
        c = temp[0];
        e = temp[1];
        temp =R(b, c, d, e, a, 3, K3, 12,  9, x);
        b = temp[0];
        d = temp[1];
        temp =R(a, b, c, d, e, 3, K3, 14, 11, x);
        a = temp[0];
        c = temp[1];
        temp =R(e, a, b, c, d, 3, K3, 15, 10, x);
        e = temp[0];
        b = temp[1];
        temp =R(d, e, a, b, c, 3, K3, 14,  0, x);
        d = temp[0];
        a = temp[1];
        temp =R(c, d, e, a, b, 3, K3, 15,  8, x);
        c = temp[0];
        e = temp[1];
        temp =R(b, c, d, e, a, 3, K3,  9, 12, x);
        b = temp[0];
        d = temp[1];
        temp =R(a, b, c, d, e, 3, K3,  8,  4, x);
        a = temp[0];
        c = temp[1];
        temp =R(e, a, b, c, d, 3, K3,  9, 13, x);
        e = temp[0];
        b = temp[1];
        temp =R(d, e, a, b, c, 3, K3, 14,  3, x);
        d = temp[0];
        a = temp[1];
        temp =R(c, d, e, a, b, 3, K3,  5,  7, x);
        c = temp[0];
        e = temp[1];
        temp =R(b, c, d, e, a, 3, K3,  6, 15, x);
        b = temp[0];
        d = temp[1];
        temp =R(a, b, c, d, e, 3, K3,  8, 14, x);
        a = temp[0];
        c = temp[1];
        temp =R(e, a, b, c, d, 3, K3,  6,  5, x);
        e = temp[0];
        b = temp[1];
        temp =R(d, e, a, b, c, 3, K3,  5,  6, x);
        d = temp[0];
        a = temp[1];
        temp =R(c, d, e, a, b, 3, K3, 12,  2, x); 
        c = temp[0];
        e = temp[1];
        /* 63 */
    /* Round 5 */
        temp = R(b, c, d, e, a, 4, K4,  9,  4, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, K4, 15,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, K4,  5,  5, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, K4, 11,  9, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, K4,  6,  7, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, K4,  8, 12, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, K4, 13,  2, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, K4, 12, 10, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, K4,  5, 14, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, K4, 12,  1, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, K4, 13,  3, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, K4, 14,  8, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, K4, 11, 11, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, K4,  8,  6, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, K4,  5, 15, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, K4,  6, 13, x); 
        b = temp[0];
        d = temp[1];
        /* 79 */
        long aa = a;
        long bb = b;
        long cc = c;
        long dd = d;
        long ee = e;
    
        
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
    /* Parallel round 1 */
        temp = R(a, b, c, d, e, 4, KK0,  8,  5, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, KK0,  9, 14, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, KK0,  9,  7, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, KK0, 11,  0, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, KK0, 13,  9, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, KK0, 15,  2, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, KK0, 15, 11, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, KK0,  5,  4, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, KK0,  7, 13, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, KK0,  7,  6, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, KK0,  8, 15, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 4, KK0, 11,  8, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 4, KK0, 14,  1, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 4, KK0, 14, 10, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 4, KK0, 12,  3, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 4, KK0,  6, 12, x);
        a = temp[0];
        c = temp[1]; 
        /* 15 */

        temp = R(e, a, b, c, d, 3, KK1,  9,  6, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 3, KK1, 13, 11, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 3, KK1, 15,  3, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 3, KK1,  7,  7, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 3, KK1, 12,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 3, KK1,  8, 13, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 3, KK1,  9,  5, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 3, KK1, 11, 10, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 3, KK1,  7, 14, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 3, KK1,  7, 15, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 3, KK1, 12,  8, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 3, KK1,  7, 12, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 3, KK1,  6,  4, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 3, KK1, 15,  9, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 3, KK1, 13,  1, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 3, KK1, 11,  2, x);
        e = temp[0];
        b = temp[1];         /* 31 */
    /* Parallel round 3 */

        temp = R(d, e, a, b, c, 2, KK2,  9, 15, x);
        d = temp[0];
        a = temp[1];

        temp = R(c, d, e, a, b, 2, KK2,  7,  5, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, KK2, 15,  1, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, KK2, 11,  3, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, KK2,  8,  7, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, KK2,  6, 14, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 2, KK2,  6,  6, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, KK2, 14,  9, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, KK2, 12, 11, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, KK2, 13,  8, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, KK2,  5, 12, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 2, KK2, 14,  2, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 2, KK2, 13, 10, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 2, KK2, 13,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 2, KK2,  7,  4, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 2, KK2,  5, 13, x);
        d = temp[0];
        a = temp[1];        
         /* 47 */
    /* Parallel round 4 */

        temp = R(c, d, e, a, b, 1, KK3, 15,  8, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, KK3,  5,  6, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, KK3,  8,  4, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, KK3, 11,  1, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, KK3, 14,  3, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, KK3, 14, 11, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, KK3,  6, 15, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, KK3, 14,  0, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, KK3,  6,  5, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, KK3,  9, 12, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, KK3, 12,  2, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 1, KK3,  9, 13, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 1, KK3, 12,  9, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 1, KK3,  5,  7, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 1, KK3, 15, 10, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 1, KK3,  8, 14, x);
        c = temp[0];
        e = temp[1];
                 /* 63 */
    /* Parallel round 5 */
        temp = R(b, c, d, e, a, 0, KK4,  8, 12, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, KK4,  5, 15, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, KK4, 12, 10, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, KK4,  9,  4, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, KK4, 12,  1, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, KK4,  5,  5, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, KK4, 14,  8, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, KK4,  6,  7, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, KK4,  8,  6, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, KK4, 13,  2, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, KK4,  6, 13, x);
        b = temp[0];
        d = temp[1];
        temp = R(a, b, c, d, e, 0, KK4,  5, 14, x);
        a = temp[0];
        c = temp[1];
        temp = R(e, a, b, c, d, 0, KK4, 15,  0, x);
        e = temp[0];
        b = temp[1];
        temp = R(d, e, a, b, c, 0, KK4, 13,  3, x);
        d = temp[0];
        a = temp[1];
        temp = R(c, d, e, a, b, 0, KK4, 11,  9, x);
        c = temp[0];
        e = temp[1];
        temp = R(b, c, d, e, a, 0, KK4, 11, 11, x);
        b = temp[0];
        d = temp[1];
        /* 79 */
        System.out.println(a + " " + b + " "+ c + " " + d + " " + e);

        long t = ((((state[1] + cc + d) % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        state[1] = ((((state[2] + dd + e) % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        state[2] = ((((state[3] + ee + a) % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        state[3] = ((((state[4] + aa + b) % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        state[4] = ((((state[0] + bb + c) % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        state[0] = (((t % 0x100000000L)) + 0x100000000L) % 0x100000000L;
        return state;
    }
}

public class Ripemd160 extends transforms{
    private byte[] Padding = new byte[64];
    
    public Ripemd160(){
        Padding[0] = (byte)0x80;
    }
    
    private RMDContext RMDUpdate(RMDContext ctx, byte arr[], int len){
        int have = ctx.count.divide(BigInteger.valueOf(8)).intValue();
        int need = 64 - have;
        ctx.count = ctx.count.add(BigInteger.valueOf(8 * len));
        int off = 0;
        if (len >= need){
            if(have != 0){
                for(int i = 0; i < need; i++){
                    ctx.buffer[have + i] = arr[i];
                }
                ctx.state = RMDTransform(ctx.state, ctx.buffer);
                off = need;
                have = 0;
            }

            while(off + 64 <= len){
                ctx.state = RMDTransform(ctx.state, Arrays.copyOfRange(arr, off, 64));
                off += 64;
            }    
        }

        if(off < len){
            for(int i = 0; i < len + off; i++){
                ctx.buffer[have + i] = arr[off + i];
            }
        }
        return ctx;
    }

    private byte[] RMDFinal(RMDContext ctx){
        byte arr_temp[] = ctx.count.toByteArray();
        byte temp;
        for (int i = 0; i < arr_temp.length / 2; i++){
            temp = arr_temp[arr_temp.length - i - 1];
            arr_temp[arr_temp.length - i - 1] = arr_temp[i];
            arr_temp[i] = temp; 
        } 
        byte[] size = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).put(arr_temp).array();
        int padlen = 64 - ((((ctx.count.divide(BigInteger.valueOf(8)).intValue() % 64)) + 64) % 64);
        if (padlen < 1 + 8){
            padlen += 64;
        }
        ctx = RMDUpdate(ctx, Padding, padlen - 8);
        ctx = RMDUpdate(ctx, size, 8);
        byte []ret_temp = ByteBuffer.allocate(8 * 5).order(ByteOrder.LITTLE_ENDIAN).putLong(ctx.state[0]).putLong(ctx.state[1]).putLong(ctx.state[2]).putLong(ctx.state[3]).putLong(ctx.state[4]).array();
        byte []ret = new byte[4 * 5];
        for (int i = 0, j = 0; i < 5 * 8; i += 8){
            ret[j++] = ret_temp[i];
            ret[j++] = ret_temp[i+1];
            ret[j++] = ret_temp[i+2];
            ret[j++] = ret_temp[i+3];
        }
        return ret;
    }
    public byte[] RMD(byte arr[]){
        return(RMDFinal(RMDUpdate(new RMDContext(), arr, arr.length)));
    }
}