package hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class hashingTest{

    public void test_sha256(){
        String str = "a longer message to make sure that a larger number of blocks works okay too";
        for(int i=0;i<15;i++){
            str +="a longer message to make sure that a larger number of blocks works okay too";
        }

        String[] test_bytes = {"","abc","hello",str};
        Sha sha256 = new Sha();

        for(int b=0;b<test_bytes.length;b++){
            // String gt = encrypt(test_bytes[b]);
            // String yolo = String.format("%02x", 0xff & sha256(test_bytes[b]));
            // assert gt == yolo;
        }
    }

    public void test_ripemd160(){
        String str="a";
        for(int i=0;i<1000;i++){
            str += str;
        }
        String[] test = {"","a","abc","message digest","12345678901234567890123456789012345678901234567890123456789012345678901234567890",str};
        String[] res = {"9c1185a5c5e9fc54612808977ee8f548b2258d31","0bdc9d2d256b3ee9daae347be6f4dc835a467ffe","8eb208f7e05d987a9b044a8e98c6b087f15a0bfc","5d0689ef49d2fae572b881b123a85ffa21595f36","9b752e45573d4b39f4dbd3323cab82bf63326bfb","aa69deee9a8922e92f8105e007f76110f381e9cf"};

        // Ripemd ripemd160 = new Ripemd();

        for(int b=0; b<test.length;b++){
            // yolo = String.format("%02x", 0xff & ripemd160(test[b].getBytes(StandardCharsets.US_ASCII)));
            // assert yolo == res[b];
        }
    }
}

