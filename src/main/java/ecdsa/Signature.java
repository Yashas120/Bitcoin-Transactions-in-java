package ecdsa;

import hashing.Sha;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.*;
import java.util.*;

import ecc.Curve;
import ecc.Generator;
import ecc.Point;

public class Signature {
    private BigInteger r;
    private BigInteger s;
    
    protected long bytesToLong(byte []arr){
        byte []conv = new byte[8];
        conv[4] = arr[0];
        conv[5] = arr[1];
        conv[6] = arr[2];
        conv[7] = arr[3];
        return ByteBuffer.wrap(conv).getLong();
    }   

    protected byte[] Bytetobyte(ArrayList<Byte> s){
        byte[] bytes = new byte[s.size()];
        int j=0;
        for(Byte b: s.toArray(new Byte[0])) {
            bytes[j++] = b.byteValue();
        }
        return bytes;
    }

    private static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", 0xFF & b));
        }
        return builder.toString();
      }

    protected byte[] longToBytes(long num){
        return  ByteBuffer.allocate(32).putLong(num).array();
    }
    
    protected byte[] dern(BigInteger n){
        byte[] temp = n.toByteArray();
        ArrayList<Byte> nb = new ArrayList<Byte>();
        for(int i=0; i<temp.length; i++){
            if(temp[i] == 0){
                temp[i] = -1;
                continue;
            }
            else if(temp[i] != 0){
                break;
            }
        }
        for(byte p : temp){
            if(p != -1){
                nb.add(p);
            }
        }
        if(nb.get(0) >= 80){
            nb.add(0,(byte)0);
        }
        return Bytetobyte(nb);
        
    }

    public Signature decode(byte[] der) throws IOException{
        InputStream s = new ByteArrayInputStream(der);
        // Read the 0x30 byte
        s.read();
        // Read total length of encoding
        s.read();
        // Read the 0x02 byte
        s.read(); 
        int rlength = s.read();
        byte[] r = new byte[rlength];
        for(int i=0; i<rlength; i++){
            r[i] = (byte) s.read();
        }
        BigInteger rval = new BigInteger(bytesToHex(r),16);
        // Read the 0x02 byte
        s.read();
        int slength = s.read();
        r = new byte[slength];
        for(int i=0; i<rlength; i++){
            r[i] = (byte) s.read();
        }
        BigInteger sval = new BigInteger(bytesToHex(r),16);
        Signature cls = new Signature();
        cls.r = rval;
        cls.s = sval;
        return cls;
    }
    
    public byte[] encode(){
        byte[] rb = dern(this.r);
        byte[] sb = dern(this.s);
        ArrayList<Byte> frame = new ArrayList<Byte>();
        frame.add((byte)30);
        frame.add((byte)(4+rb.length+sb.length));
        frame.add((byte)2);
        frame.add((byte)rb.length);
        for(byte b : rb){
            frame.add(b);
        }
        frame.add((byte)2);
        frame.add((byte)sb.length);
        for(byte b : sb){
            frame.add(b);
        }
        return Bytetobyte(frame);
    }

    public Signature sign(BigInteger secret_key, byte[] message) throws IOException{
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
        BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
        BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        
        Curve bitcoinCurve = new Curve(p,a,b);
        Point G = new Point(bitcoinCurve,x,y);
        Generator gen = new Generator(G, n);
        n = gen.n;
        Sha sha = Sha.getSha();
        byte [] sha1 = sha.sha256(message);
        byte [] sha2 = sha.sha256(sha1);
        BigInteger z = new BigInteger(bytesToHex(sha2), 16);

        BigDecimal term2 = new BigDecimal(n.subtract(BigInteger.ONE));
        BigDecimal term3 = new BigDecimal(BigInteger.ONE);
        
        BigInteger seed = new BigInteger(bytesToHex(message),16);
        Random robj = new Random();
        robj.setSeed(seed.intValue());

        BigDecimal sk1 = BigDecimal.valueOf(Math.random()).multiply(term2).add(term3);
        System.out.println("decimal sk : "+sk1);
        BigInteger sk = sk1.toBigInteger();
        System.out.println("integer sk : "+sk);
        // BigInteger sk = BigInteger.ONE;
        Point P = G.multiply(sk);
        
        BigInteger rt = P.x;
        BigInteger f1 =  P.inv(sk, n);
        BigInteger f2 = secret_key.multiply(rt).add(z);
        System.out.println("f1 : "+f1);
        System.out.println("f2 : "+f2);
        BigInteger st = f1.multiply(f2).mod(n).add(n).mod(n);

        System.out.println("s : "+st);
        System.out.println("n : "+n);
        BigInteger test = n.divide(new BigInteger("2"));
        if(st.compareTo(test) == 1){
            st = n.subtract(st);
        }
        System.out.println(st);
        Signature s = new Signature();
        s.r = rt;
        s.s = st;
        return s;
    }
    
    public boolean verify(Point public_key, byte[] message, Signature sig){
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
        BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
        BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        
        Curve bitcoinCurve = new Curve(p,a,b);
        Point G = new Point(bitcoinCurve,x,y);
        Generator gen = new Generator(G, n);
        n = gen.n;

        Sha sha = Sha.getSha();
        BigInteger z = new BigInteger(bytesToHex(sha.sha256(sha.sha256(message))),16);

        BigInteger w = G.inv(sig.s, n);
        BigInteger u1 = z.multiply(w).mod(n);
        BigInteger u2 = sig.r.multiply(w).mod(n);
        G.x = u1.multiply(gen.G.x).add(u2.multiply(public_key.x));
        return G.x == sig.r;  
    }

    @Override 
    public String toString(){
        return "r: " + this.r + "s: " + this.s;
    }
    
}

// 90058095591498491416238072578713788397783575082545596483785475522013478186080
// 115792089237316195423570985008687907852837564279074904382605163141518161494337