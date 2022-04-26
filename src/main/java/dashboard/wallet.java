package dashboard;

import java.math.BigInteger;
import java.nio.charset.Charset;
import org.json.JSONObject;
import org.json.JSONException;
import org.json.JSONArray;
import ecc.Curve;
import ecc.Generator;
import ecc.Point;
import ecc.PublicKey;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Wallet {

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
    Wallet( String name, String key){
        this.name = name;
        this.secretKey = key;
        this.balance = 0;
        BigInteger secretKeyInt = new BigInteger(toHex(secretKey),16);
        Point publicKey = G.multiply(secretKeyInt);
        System.out.println("Wallet Name : "+name);
        System.out.println("Secret Key : "+secretKey);
        System.out.println("Public Key : \nx : "+publicKey.x+"\ny : "+publicKey.y);
        System.out.println("Public Key generated is on curve : \033[92m" + publicKey.verify_on_curve()+"\033[0m");
        this.addr = PublicKey.toPublicKey(publicKey).address("test", true);
        System.out.println("\nBitcoin addr : "+ this.addr);
        System.out.println("Length of addr : "+this.addr.length());
        System.out.println("-------------------------------------------------------------------");
    }

    public Boolean newWallet() throws IOException, InterruptedException, JSONException{
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://blockstream.info/testnet/api/address/" + this.addr))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // System.out.println((response));
        JSONObject body = new JSONObject(response.body());
        // System.out.println(body);
        JSONObject chain_stats = (JSONObject)(body.get("chain_stats"));
        // System.out.println(body.get("chain_stats"));
        // System.out.println(chain_stats.get("tx_count"));
        if((int)chain_stats.get("tx_count") == 0){
            return true;
        }
    

        return false;
    }

    public static void main(String[] args) {
        try{

            Wallet w = new Wallet("test wallet", "vishal");
            System.out.println("Is new Wallet ? " + w.newWallet());
        }
        catch(Exception err){
            System.out.println(err);
        }
    }
}