package dashboard;

import java.math.BigInteger;
import java.nio.charset.Charset;
import org.json.JSONObject;
import org.json.JSONException;
import ecc.Curve;
import ecc.Generator;
import ecc.Point;
import ecc.PublicKey;

public class Wallet{

    String name;
    String secretKey;
    float balance;
    String addr;
    BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
    BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
    BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    Curve bitcoinCurve = new Curve(p,a,b);
    Point G = new Point(bitcoinCurve,x,y);
    Generator bitcoinGenerator = new Generator(G, n);
    
    public static String toHex(String arg) {
        return String.format("%040x", new BigInteger(1, arg.getBytes(Charset.forName("UTF-8"))));
    }

    public Wallet( String name, String key){
        this.name = name;
        this.secretKey = key;
        this.balance = 0;
        BigInteger secretKeyInt = new BigInteger(toHex(secretKey),16);
        Point publicKey = G.multiply(secretKeyInt);
        System.out.println("Wallet Name : "+name);
        System.out.println("Secret Key : "+secretKey);
        System.out.println("Public Key : \nx : "+publicKey.x+"\ny : "+publicKey.y);
        System.out.println("Public Key generated is on curve : \033[92m" + publicKey.verify_on_curve()+"\033[0m");
        String pbk1 = PublicKey.toPublicKey(publicKey).address("test", true);
        System.out.println("\nBitcoin addr : "+pbk1);
        System.out.println("Length of addr : "+pbk1.length());
        System.out.println("-------------------------------------------------------------------");
    }

    public Boolean newWallet(){
    try {
            JSONObject jsonObject = new JSONObject("{\"phonetype\":\"N95\",\"cat\":\"WP\"}");
            System.out.println(jsonObject);
    }
    catch (JSONException err){
            System.out.println("Error : " + err.toString());
    }

        return false;
    }

    public static void main(String[] args) {
        Wallet w = new Wallet("test wallet", "vishal");
        System.out.println(w.newWallet());
    }
}
