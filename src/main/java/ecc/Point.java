package ecc;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Hashtable;
/*
Point class is used to define a starting generator point on the curve.
This point marks the beginning of random walk on the curve.
The values of x, y are assigned to the publicly know starting points for the curve.
*/

public class Point{
  public Curve ecc_curve;
  public BigInteger x;
  public BigInteger y;

  private BigInteger infx = new BigInteger("0");
  private BigInteger infy = new BigInteger("0");
  private Curve inf_curve = this.ecc_curve;

  public Point(Curve curve, BigInteger x, BigInteger y){
    this.ecc_curve = curve;
    this.x = x;
    this.y = y;
  }

  public boolean verify_on_curve(){
    BigInteger is_on_curve = ((this.y.pow(2)).subtract(this.x.pow(3)).subtract(this.ecc_curve.b)).mod(this.ecc_curve.p);
    boolean flag = false;
    if(is_on_curve.intValue() == 0){
      flag = true;
    }
    return flag;
  }

  private BigInteger[] gcd(BigInteger a, BigInteger b){

    BigInteger return_val[] = new BigInteger[3];

    BigInteger zeros = new BigInteger("0");
    BigInteger ones = new BigInteger("1");

    BigInteger old_r=a, r=b;
    BigInteger old_s = ones, s = zeros;
    BigInteger old_t = zeros, t = ones;
    
    while(!r.equals(zeros)){
      BigDecimal d_old_r = new BigDecimal(old_r);
      BigDecimal d_r = new BigDecimal(r);
      
      BigDecimal d_quotient = d_old_r.divide(d_r, 0, RoundingMode.FLOOR);
      BigInteger quotient = d_quotient.toBigInteger();

      BigInteger r_temp = old_r.subtract(quotient.multiply(r));
      BigInteger old_r_temp = r;
      r = r_temp;
      old_r = old_r_temp;

      BigInteger s_temp = old_s.subtract(quotient.multiply(s));
      BigInteger old_s_temp = s;
      s = s_temp;
      old_s = old_s_temp;

      BigInteger t_temp = old_t.subtract(quotient.multiply(t));
      BigInteger old_t_temp = t;
      t = t_temp;
      old_t = old_t_temp;
    }
    return_val[0] = old_r;
    return_val[1] = old_s;
    return_val[2] = old_t;
    return return_val;
  }

  public BigInteger inv(BigInteger n, BigInteger p){
    BigInteger return_val[];
    return_val = gcd(n, p);
    return return_val[1].mod(p);
  }

  public Point add(Point other){
    // handle special case of P + 0 = 0 + P = 0
    if (this.x.equals(this.infx) && this.y.equals(this.infy) && this.ecc_curve == this.inf_curve){
      return other;
    }
    if (other.x.equals(other.infx) && other.y.equals(other.infy) && other.ecc_curve == other.inf_curve){
      return this;
    }
    // handle special case of P + (-P) = 0
    if (this.x.equals(other.x) && !this.y.equals(other.y)){
      return new Point(this.inf_curve, this.infx, this.infy);
    }
    BigInteger m;
    if(this.x.equals(other.x)){ // (self.y = other.y is guaranteed too per above check)
      m = (this.x.pow(2).multiply(new BigInteger("3")).add(this.ecc_curve.a)).multiply(inv(this.y.multiply(new BigInteger("2")), this.ecc_curve.p));
    }
    else{
      m = (this.y.subtract(other.y)).multiply(inv(this.x.subtract(other.x), this.ecc_curve.p));
    }
    // compute the new point
    BigInteger rx, ry;
    rx = (m.pow(2).subtract(this.x).subtract(other.x)).mod(this.ecc_curve.p);
    ry = (rx.subtract(this.x).multiply(m).add(this.y).multiply(new BigInteger("-1"))).mod(this.ecc_curve.p);
    return new Point(this.ecc_curve, rx, ry);
  }

  public Point multiply(BigInteger k){
    Point result = new Point(this.inf_curve, this.infx, this.infy);
    Point append = this;
    BigInteger zero = new BigInteger("0");
    BigInteger one = new BigInteger("1");
    while (!k.equals(zero)){
      if (!(k.and(one)).equals(zero)){
        result = result.add(append);
      }
      append = append.add(append);
      k = k.shiftRight(1);
    }
    return result;
  }

  public String toString(){
    Hashtable <String, Object> dictionary = new Hashtable<String, Object>();
    dictionary.put("ecc_curve", this.ecc_curve.toString());
    dictionary.put("x", this.x);
    dictionary.put("y", this.y);
    return dictionary.toString();
  }
}