package hashing;
/* Follows the FIPS PUB 180-4 description for calculating SHA-256 hash function
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf*/

import java.lang.Math;
import java.nio.*;
import java.util.Arrays;

class shaFunctions{
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    protected static long maxSize = (long)Math.pow(2,32); 
    private long shiftRight(long num,long shift){
        return num >> shift;
    }

    private long rotateRight(long num, long shift){
        return (num >> shift) | (num << 32 - shift) & (maxSize - 1);
    }

    protected long sigmoid0(long num){
        return rotateRight(num, 7) ^ rotateRight(num, 18) ^ shiftRight(num, 3) ;
    }

    protected long sigmoid1(long num){
        return rotateRight(num, 17) ^ rotateRight(num, 19) ^ shiftRight(num, 10) ;
    }

    protected long capitalSigmoid0(long num){
        return rotateRight(num, 2) ^ rotateRight(num, 13) ^ rotateRight(num, 22) ;
    }

    protected long capitalSigmoid1(long num){
        return rotateRight(num, 6) ^ rotateRight(num, 11) ^ rotateRight(num, 25) ;
    }

    protected long ch(long num1,long num2, long num3){
        return (num1 & num2) ^ (~num1 & num3) ;
    }

    protected long maj(long num1, long num2, long num3){
        return (num1 & num2) ^ (num1 & num3) ^ (num2 & num3);
    }

    protected long bytesToLong(byte []arr){
        byte []conv = new byte[8];
        conv[4] = arr[0];
        conv[5] = arr[1];
        conv[6] = arr[2];
        conv[7] = arr[3];
        return ByteBuffer.wrap(conv).getLong();
    }   

    protected byte[] longToBytes(long num){
        return  Arrays.copyOfRange(ByteBuffer.allocate(8).putLong(num).array(), 4, 8);
    }

    protected String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    protected byte[] pad(byte[] arr){
        // Follows Section 5.1: Padding the message 
        int len =  (int)Math.ceil((arr.length+1)/ 64.0) * 64;
        byte[] b = new byte[len];
        int j = 0;
        long l = 0;
        for(byte i : arr){
            b[j++] = i;
            l++;
        }
        b[j] = (byte)10000000;
        j = len - 8;
        for (byte i :  ByteBuffer.allocate(8).putLong(l * 8).array()){
            b[j++] = i;
        }
        // System.out.println(Arrays.toString(b));
        return b;

    }
}

class shaConstants extends shaFunctions{
    private long []nPrimes(int n){
        short flag;
        long []arr = new long[n];
        int count = 0;
        for(int i = 2; count < n; i++){
            flag = 1;
            for(int j = 2; j*j <= i; j++){
                if (i % j == 0){
                    flag = 0;
                    break;
                }
            }
            if(flag == 1){
                arr[count++] = i;
            }
        }
        return arr;
    }

    private static long fractionalPart(Double frac){
        // return the first n bits of fractional part of float f
        frac -= Math.floor(frac);
        frac *= maxSize;
        return(frac.longValue());
    }

    protected long[] genK(){
        /*
            The first 32 bits of the fractional parts of the cube roots of the first
            64 prime numbers:
        
            428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
            d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
            e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
            983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
            27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
            a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
            19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
            748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
        */
        long[] primes = nPrimes(64);
        for(int i = 0; i < primes.length; i++){
            primes[i] = fractionalPart(Math.pow(primes[i],(1/3.0)));
        }
        return primes;

    }

    protected long[] genH(){
        /*
            Follows Section 5.3.3 to generate the initial hash value H^0

            The first 32 bits of the fractional parts of the square roots of
            the first 8 prime numbers.

            6a09e667 bb67ae85 3c6ef372 a54ff53a 9b05688c 510e527f 1f83d9ab 5be0cd19
        */
        long[] primes = nPrimes(8);
        for(int i = 0; i < primes.length; i++){
            primes[i] = fractionalPart(Math.pow(primes[i],(1/2.0)));
        }
        return primes;
    }
}


public class Sha extends shaConstants{
    private long[] _K = super.genK();
    private long[] _H = super.genH();
    public byte[] sha256(byte[] arr){
        long []K = Arrays.copyOf(_K , _K.length);
        long []H = Arrays.copyOf(_H , _H.length);
        byte []byte_arr = super.pad(arr);
        // System.out.println(super.bytesToHex(byte_arr));
        for (int block = 0; block < byte_arr.length/64; block++){

           // 1. Prepare the message schedule, a 64-entry array of 32-bit words

            byte [][]W = new byte[64][4];
            int index;
            for (int t = 0; t < 16; t++){
                index = (block * 64) + t*4;
                W[t][0] = byte_arr[index];
                W[t][1] = byte_arr[index+1];
                W[t][2] = byte_arr[index+2];
                W[t][3] = byte_arr[index+3];
                // System.out.println(super.bytesToHex(W[t]));
            }
            long t1, t2, t3, t4;
            byte []total = new byte[4];
            for (int t = 16; t < 64; t++){
                t1 = super.sigmoid1(super.bytesToLong(W[t-2]));
                t2 = super.bytesToLong(W[t-7]);
                t3 = super.sigmoid0(super.bytesToLong(W[t-15]));
                t4 = super.bytesToLong(W[t-16]);
                total = super.longToBytes((long)((t1 + t2 + t3 + t4) % maxSize));
                W[t][0] = total[0];
                W[t][1] = total[1];
                W[t][2] = total[2];
                W[t][3] = total[3];
                // System.out.println(super.bytesToHex(W[t]));
            }
            // long a = H[0] , b = H[1], c = H[2], d = H[3], e = H[4], f  = H[5], g = H[6], h = H[7]
            long T1 = 0, T2 = 0;
            long []delta = Arrays.copyOf(H, H.length);
            for(int t = 0; t < 64; t++){
                T1 = (delta[7] + capitalSigmoid1(delta[4]) + ch(delta[4], delta[5], delta[6]) + K[t] + bytesToLong(W[t])) % maxSize;
                T2 = (capitalSigmoid0(delta[0]) + maj(delta[0], delta[1], delta[2])) % maxSize;
                delta[7] = delta[6];
                delta[6] = delta[5];
                delta[5] = delta[4];
                delta[4] = (delta[3] + T1) % maxSize;
                delta[3] = delta[2];
                delta[2] = delta[1];
                delta[1] = delta[0];
                delta[0] = (T1 + T2) % maxSize;
            }
            // 4. Compute the i-th intermediate hash value H^i
            H[0] = (H[0] + delta[0]) % maxSize;
            H[1] = (H[1] + delta[1]) % maxSize;
            H[2] = (H[2] + delta[2]) % maxSize;
            H[3] = (H[3] + delta[3]) % maxSize;
            H[4] = (H[4] + delta[4]) % maxSize;
            H[5] = (H[5] + delta[5]) % maxSize;
            H[6] = (H[6] + delta[6]) % maxSize;
            H[7] = (H[7] + delta[7]) % maxSize;
        }
        byte[][] ret = new byte[8][4];
        ret[0] = super.longToBytes((long)H[0]);
        ret[1] = super.longToBytes((long)H[1]);
        ret[2] = super.longToBytes((long)H[2]);
        ret[3] = super.longToBytes((long)H[3]);
        ret[4] = super.longToBytes((long)H[4]);
        ret[5] = super.longToBytes((long)H[5]);
        ret[6] = super.longToBytes((long)H[6]);
        ret[7] = super.longToBytes((long)H[7]);

        byte hash[] = new byte[32];
        hash[0] = ret[0][0]; hash[1] = ret[0][1]; hash[2] = ret[0][2]; hash[3] = ret[0][3];
        hash[4] = ret[1][0]; hash[5] = ret[1][1]; hash[6] = ret[1][2]; hash[7] = ret[1][3];
        hash[8] = ret[2][0]; hash[9] = ret[2][1]; hash[10] = ret[2][2]; hash[11] = ret[2][3];
        hash[12] = ret[3][0]; hash[13] = ret[3][1]; hash[14] = ret[3][2]; hash[15] = ret[3][3];
        hash[16] = ret[4][0]; hash[17] = ret[4][1]; hash[18] = ret[4][2]; hash[19] = ret[4][3];
        hash[20] = ret[5][0]; hash[21] = ret[5][1]; hash[22] = ret[5][2]; hash[23] = ret[5][3];
        hash[24] = ret[6][0]; hash[25] = ret[6][1]; hash[26] = ret[6][2]; hash[27] = ret[6][3];
        hash[28] = ret[7][0]; hash[29] = ret[7][1]; hash[30] = ret[7][2]; hash[31] = ret[7][3];
        return hash;
    }

}
