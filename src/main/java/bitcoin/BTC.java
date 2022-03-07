package bitcoin;

import java.math.BigInteger;
import java.nio.charset.Charset;
import ecc.Curve;
import ecc.Point;
import ecc.Generator;
import ecc.PublicKey;

public class BTC{
  public static String toHex(String arg) {
    return String.format("%040x", new BigInteger(1, arg.getBytes(Charset.forName("UTF-8"))));
  }
  public static void main(String []args){

    BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
    BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
    BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    
    Curve bitcoinCurve = new Curve(p,a,b);
    Point G = new Point(bitcoinCurve,x,y);
    Generator bitcoinGenerator = new Generator(G, n);

    System.out.println("Curve Parameters : \n"+bitcoinCurve.toString());
    System.out.println("Seed Point parameters : \n"+G.toString());
    System.out.println("Generator parameters : \n"+bitcoinGenerator.toString());
    System.out.println("Generator Point is on curve : " + G.verify_on_curve());
    
    int sk1 = 1;
    Point pk1 = G;
    System.out.println("Secret Key : "+sk1+"\nPublic Key : \nx : "+pk1.x+"\ny : "+pk1.y);
    System.out.println("Generated Point is on curve : " + pk1.verify_on_curve());
    System.out.println("-------------------------------------------------------------------");
    int sk2 = 2;
    
    long startTime = System.nanoTime();
    Point pk2 = G.add(G);
    long endTime = System.nanoTime();
    long duration = (endTime - startTime);  //divide by 1000000 to get milliseconds
    System.out.println("Secret Key : "+sk2+"\nPublic Key : \nx : "+pk2.x+"\ny : "+pk2.y);
    System.out.println("Generated Point is on curve : " + pk2.verify_on_curve());
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");
    int sk3 = 3;

    startTime = System.nanoTime();
    Point pk3 = G.add(G).add(G);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("Secret Key : "+sk3+"\nPublic Key : \nx : "+pk3.x+"\ny : "+pk3.y);
    System.out.println("Generated Point is on curve : " + pk3.verify_on_curve());
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------\n");

    int msk1 = 1;
    Point mpk1 = G;
    System.out.println("Secret Key : "+msk1+"\nPublic Key : \nx : "+mpk1.x+"\ny : "+mpk1.y);
    System.out.println("Generated Point is on curve : " + mpk1.verify_on_curve());
    System.out.println("-------------------------------------------------------------------");

    int msk2 = 2;
    startTime = System.nanoTime();
    Point mpk2 = G.multiply(new BigInteger("2"));
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("Secret Key : "+msk2+"\nPublic Key : \nx : "+mpk2.x+"\ny : "+mpk2.y);
    System.out.println("Generated Point is on curve : " + mpk2.verify_on_curve());
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    int msk3 = 3;
    startTime = System.nanoTime();
    Point mpk3 = G.multiply(new BigInteger("3"));
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("Secret Key : "+msk3+"\nPublic Key : \nx : "+mpk3.x+"\ny : "+mpk3.y);
    System.out.println("Generated Point is on curve : " + mpk3.verify_on_curve());
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    String secretKey_string = "Andrej is cool :P";
    BigInteger secretKey = new BigInteger(toHex(secretKey_string),16);
    System.out.println("secret key int : "+secretKey);
    startTime = System.nanoTime();
    Point publicKey = G.multiply(secretKey);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    System.out.println("Secret Key : "+secretKey_string);
    System.out.println("Public Key : \nx : "+publicKey.x+"\ny : "+publicKey.y);
    System.out.println("Public Key generated is on curve : \033[92m" + publicKey.verify_on_curve()+"\033[0m");
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    startTime = System.nanoTime();
    String pk = PublicKey.toPublicKey(publicKey).address("test", true);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("\nPublic Key : "+pk);
    System.out.println("Length of Public Key : "+pk.length());
    System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");
  }
}