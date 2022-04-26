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
    Point publicKey;
    BigInteger secretKeyInt;
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
        this.secretKeyInt = new BigInteger(toHex(secretKey),16);
        this.publicKey = G.multiply(secretKeyInt);

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

    public Float getBalance() throws IOException, InterruptedException, JSONException{
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
        this.balance = Float.parseFloat(chain_stats.get("funded_txo_sum").toString()) - Float.parseFloat(chain_stats.get("spent_txo_sum").toString());
        this.balance *= 0.00000001;
        return this.balance;
    }

    public String latestTx() throws IOException, InterruptedException, JSONException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://blockstream.info/testnet/api/address/" + this.addr + "/txs"))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // System.out.println((response.body()));
        JSONArray body = new JSONArray(response.body());
        // System.out.println(body);
        
        JSONObject addr = (JSONObject)(body.getJSONObject(0));
        // System.out.println(body.get("chain_stats"));
        // System.out.println(chain_stats.get("tx_count"));
        return addr.get("txid").toString();

    }

    public void txBroadcast(String msg) throws IOException, InterruptedException, JSONException{

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://blockstream.info/testnet/api/tx"))
                .POST(HttpRequest.BodyPublishers.ofString(msg))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.body());

    }

    public void txDetails(String tx) throws IOException, InterruptedException, JSONException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://blockstream.info/testnet/api/tx/" + tx))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        // System.out.println((response.body()));
        JSONObject body = new JSONObject(response.body());
        // System.out.println(body);
        
        JSONArray arr = (JSONArray)(body.get("vin"));
        JSONObject inWallet = (JSONObject)arr.getJSONObject(0);
        inWallet = (JSONObject)inWallet.get("prevout");

        // System.out.println(body.get("chain_stats"));
        // System.out.println(chain_stats.get("tx_count"));
        arr = (JSONArray)(body.get("vout"));
        JSONObject outWallet1 = (JSONObject)arr.getJSONObject(0);
        JSONObject outWallet2 = (JSONObject)arr.getJSONObject(1);

        System.out.println("Wallet " + inWallet.get("scriptpubkey_address").toString() + " sent " + Float.parseFloat(inWallet.get("value").toString()) * 1E-8 + "BTC");
        System.out.println("Wallet " + outWallet1.get("scriptpubkey_address").toString() + " received " + Float.parseFloat(outWallet1.get("value").toString()) * 1E-8 + "BTC");
        System.out.println("Wallet " + outWallet2.get("scriptpubkey_address").toString() + " received " + Float.parseFloat(outWallet2.get("value").toString()) * 1E-8 + "BTC");
        System.out.println("Fee : " + Float.parseFloat(body.get("fee").toString()) * 1E-8 + "BTC");

    }

    public static void main(String[] args) {
        try{

            Wallet w = new Wallet("test wallet", "Andrej is cool :P");
            System.out.println("Is new Wallet ? " + w.newWallet());
            System.out.println("Latest Transaction " + w.latestTx());
            System.out.println("Balance :" + w.getBalance());
            w.txDetails("586593509c188c9334eb134d54f8ff0b7245af1486e2104dfdf9ce7fc74636b8");
            w.txBroadcast("010000000269adb42422fb021f38da0ebe12a8d2a14c0fe484bcb0b7cb365841871f2d5e24000000006a4730440220199a6aa56306cebcdacd1eba26b55eaf6f92eb46eb90d1b7e7724bacbe1d19140220101c0d46e033361c60536b6989efdd6fa692265fcda164676e2f49885871038a0121039ac8bac8f6d916b8a85b458e087e0cd07e6a76a6bfdde9bb766b17086d9a5c8affffffff69adb42422fb021f38da0ebe12a8d2a14c0fe484bcb0b7cb365841871f2d5e24010000006b48304502210084ec4323ed07da4af6462091b4676250c377527330191a3ff3f559a88beae2e2022077251392ec2f52327cb7296be89cc001516e4039badd2ad7bbc950c4c1b6d7cc012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0118730100000000001976a9140ce17649c1306c291ca9e587f8793b5b06563cea88ac00000000");
        }
        catch(Exception err){
            System.out.println(err);
        }
    }
}