package ecc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.Charset;

import org.junit.Test;

public class eccTest {
  BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
  BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
  BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
  BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
  BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
  
  public static String toHex(String arg) {
    return String.format("%040x", new BigInteger(1, arg.getBytes(Charset.forName("UTF-8"))));
  }

  @Test
  public void point_short_add_test(){
    Curve curve = new Curve(p, a, b);
    Point G = new Point(curve, x,y);
    // String secret_key = "3";
    G = G.add(G).add(G);
    BigInteger expectedx = new BigInteger("112711660439710606056748659173929673102114977341539408544630613555209775888121");
    BigInteger expectedy = new BigInteger("25583027980570883691656905877401976406448868254816295069919888960541586679410");
    String description = "Short ECC point add";
    try{
      assertEquals(expectedx, G.x);
      assertEquals(expectedy, G.y);
      assertTrue(G.verify_on_curve());
      System.out.println(description + " - \033[92mpassed\033[0m");
    }catch(AssertionError e){
        System.out.println(description + " - \033[91mfailed\033[0m");
      throw e;
    }
  }

  @Test
  public void point_long_add_test(){
    Curve curve = new Curve(p, a, b);
    Point G = new Point(curve, x,y);
    // String secret_key = "3";
    G = G.add(G).add(G).add(G).add(G).add(G).add(G).add(G).add(G).add(G);
    BigInteger expectedx = new BigInteger("72488970228380509287422715226575535698893157273063074627791787432852706183111");
    BigInteger expectedy = new BigInteger("62070622898698443831883535403436258712770888294397026493185421712108624767191");
    String description = "Long ECC point add";
    try{
      assertEquals(expectedx, G.x);
      assertEquals(expectedy, G.y);
      assertTrue(G.verify_on_curve());
      System.out.println(description + " - \033[92mpassed\033[0m");
    }catch(AssertionError e){
        System.out.println(description + " - \033[91mfailed\033[0m");
      throw e;
    }
  }

  @Test
  public void point_space_secret_key(){
    Curve curve = new Curve(p, a, b);
    Point G = new Point(curve, x,y);
    BigInteger secretKey = new BigInteger(toHex(" "),16);
    G = G.multiply(secretKey);
    BigInteger expectedx = new BigInteger("95440839670107969455973995843666399663662641812074432045896568980475242364517");
    BigInteger expectedy = new BigInteger("67400892360194400039319989411395972789004161889863182881857158544061243615929");
    String description = "space secret key";
    try{
      assertEquals(new BigInteger("32"), secretKey);
      assertEquals(expectedx, G.x);
      assertEquals(expectedy, G.y);
      assertTrue(G.verify_on_curve());
      System.out.println(description + " - \033[92mpassed\033[0m");
    }catch(AssertionError e){
        System.out.println(description + " - \033[91mfailed\033[0m");
      throw e;
    }
  }

  @Test
  public void point_tough_secret_key(){
    Curve curve = new Curve(p, a, b);
    Point G = new Point(curve, x,y);
    
    String secretKey_string = "_yrk<Rz{xtNI2nxh-q8mvE8ukwbDEOQLH)rs&kWA)kXKo*r m>be7Ng*RHGfLgut08*Ew>IwwD{h?fE)RB(7nFLuPylyQiAxYhxwMbyd^(R&>oy6WBOkT&yWPuwHBt{BqH-pFqmA2PM)AzgVM_UM;6{$tJiT+6h {kPCmGkvPUh6B?)x_ng{x@*o(tSvA|Ak@tV(ob=";
    BigInteger expectedSecretKey = new BigInteger("64773904892189424650623596182827208874631779838793845654828791137613274747315303641475554299193235089603468180846331886664752858470421018921535490911511470433104687394241339153172152119108174652136127198312106667208480599084513077338160285497797897998727812728967149866059980346212051898926039084711561827157754147130313308450509984756994272841997584202787717845249019157295985838714551027191937697729171991861666249716524343794439358993266349651490401996309244661926592578019901");

    BigInteger secretKey = new BigInteger(toHex(secretKey_string),16);
    
    G = G.multiply(secretKey);
    BigInteger expectedx = new BigInteger("93709308251719379171912892844854393740387970949337600343564883758518494492811");
    BigInteger expectedy = new BigInteger("113255582048810676581111405841386767654579450998162618008269151592948100713260");
    String description = "tough secret key";
    try{
      assertEquals(expectedSecretKey, secretKey);
      assertEquals(expectedx, G.x);
      assertEquals(expectedy, G.y);
      assertTrue(G.verify_on_curve());
      System.out.println(description + " - \033[92mpassed\033[0m");
    }catch(AssertionError e){
        System.out.println(description + " - \033[91mfailed\033[0m");
      throw e;
    }
  }
}
