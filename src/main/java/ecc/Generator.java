package ecc;
/*
Generator class that wraps around Point Class
This class is mainly used for generating a point after traversing n orders on the curve
*/

import java.math.BigInteger;
import java.util.Hashtable;

public class Generator{
  public Point G;
  public BigInteger n;

  public Generator(Point G, BigInteger n){
    this.G = G;
    this.n = n;
  }

  public String toString(){
    Hashtable <String, Object> dictionary = new Hashtable<String, Object>();
    dictionary.put("G", this.G.toString());
    dictionary.put("n", this.n);
    return dictionary.toString();
  }
}
