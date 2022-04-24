package ecdsa;

import hashing.Sha;

import java.io.*;
import java.math.BigInteger;
import java.nio.*;
import java.util.*;

import ecc.Curve;
import ecc.Generator;
import ecc.Point;

public class Signature {
    private long r;
    private long s;
    
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

    protected byte[] longToBytes(long num){
        return  ByteBuffer.allocate(32).putLong(num).array();
    }
    
    protected byte[] dern(long n){
        byte[] temp = longToBytes(n);
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
        long rval = bytesToLong(r);
        // Read the 0x02 byte
        s.read();
        int slength = s.read();
        r = new byte[slength];
        for(int i=0; i<rlength; i++){
            r[i] = (byte) s.read();
        }
        long sval = bytesToLong(r);
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

    public Signature sign(int secret_key, byte[] message) throws IOException{
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
        long z = bytesToLong(sha.sha256(sha.sha256(message)));
        long sk = (long) ((Math.random() * (n.intValue() - 1)) + 1);
        G.x = BigInteger.valueOf(sk).multiply(gen.G.x);
    
        long rt = G.x.longValue();
        BigInteger f1 =  G.inv(BigInteger.valueOf(sk), n);
        BigInteger f2 = BigInteger.valueOf(z).add(BigInteger.valueOf((long)(secret_key * r)));
        BigInteger st =f1.multiply(f2).mod(n);
        if(st.compareTo(n.divide(BigInteger.valueOf(2))) == -1){
            st = n.subtract(st);
        }
    
        Signature s = new Signature();
        s.r = rt;
        s.s = st.longValue();
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
        long z = bytesToLong(sha.sha256(sha.sha256(message)));

        BigInteger w = G.inv(BigInteger.valueOf(sig.s), n);
        BigInteger u1 = BigInteger.valueOf(z).multiply(w).mod(n);
        BigInteger u2 = BigInteger.valueOf(sig.r).multiply(w).mod(n);
        G.x = u1.multiply(gen.G.x).add(u2.multiply(public_key.x));
        return G.x == BigInteger.valueOf(sig.r);  
    }
    
}
