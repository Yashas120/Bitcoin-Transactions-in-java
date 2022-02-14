package ecc;
/*
Eliptical Curve Cryptography (ECC)
Bitcoin uses secp256k1 curve instead of standard RSA

Elliptic Curve over the field of integers modulo a prime.
Points on the curve must satisfy the following equation
yˆ2 = xˆ3 + a*x + b mod p 
*/

import java.math.BigInteger;
import java.util.Hashtable;

public class Curve{
  public BigInteger p;
  public BigInteger a;
  public BigInteger b;

  public Curve(BigInteger p, BigInteger a, BigInteger b){
    this.a = a;
    this.b = b;
    this.p = p;
  }
 
  public String toString(){
    Hashtable <String, BigInteger> dictionary = new Hashtable<String, BigInteger>();
    dictionary.put("a", this.a);
    dictionary.put("b", this.b);
    dictionary.put("p", this.p);
    return dictionary.toString();
  }
}
