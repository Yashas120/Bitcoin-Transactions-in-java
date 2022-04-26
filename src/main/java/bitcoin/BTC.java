package bitcoin;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;

import ecc.Curve;
import ecc.Point;
import ecc.Generator;
import ecc.PublicKey;
import transaction.TxIn;
// import scraper.ParseBlockChain;
import transaction.TxOut;
import transaction.Script;
import transaction.Tx;
import ecdsa.Signature;

public class BTC{
  public static String toHex(String arg) {
    return String.format("%040x", new BigInteger(1, arg.getBytes(Charset.forName("UTF-8"))));
  }

  private static String bytesToHex(byte[] in) {
    final StringBuilder builder = new StringBuilder();
    for(byte b : in) {
        builder.append(String.format("%02x", 0xFF & b));
    }
    return builder.toString();
  }
  public static void main(String []args) throws Exception{

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

    String secretKey_string = "12345678900987654321";
    // String secretKey_string = "vishal";
    BigInteger secretKey = new BigInteger(toHex(secretKey_string),16);
    System.out.println(secretKey);
    startTime = System.nanoTime();
    Point publicKey = G.multiply(secretKey);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    System.out.println("Secret Key : "+secretKey_string);
    System.out.println("Public Key : \nx : "+publicKey.x+"\ny : "+publicKey.y);
    System.out.println("Public Key generated is on curve : \033[92m" + publicKey.verify_on_curve()+"\033[0m");
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    String secretKey_string2 = "1234567890098765432112345678900";
    BigInteger secretKey2 = new BigInteger(toHex(secretKey_string2),16);
    System.out.println(secretKey2);
    startTime = System.nanoTime();
    Point publicKey2 = G.multiply(secretKey2);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    System.out.println("Secret Key : "+secretKey_string2);
    System.out.println("Public Key : \nx : "+publicKey2.x+"\ny : "+publicKey2.y);
    System.out.println("Public Key generated is on curve : \033[92m" + publicKey2.verify_on_curve()+"\033[0m");
    System.out.println("Time : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    startTime = System.nanoTime();
    String pbk1 = PublicKey.toPublicKey(publicKey).address("test", true);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("\nBitcoin addr : "+pbk1);
    System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+pbk1);
    System.out.println("Length of addr : "+pbk1.length());
    System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------");

    startTime = System.nanoTime();
    String pbk2 = PublicKey.toPublicKey(publicKey2).address("test", true);
    endTime = System.nanoTime();
    duration = (endTime - startTime);
    
    System.out.println("\nBitcoin addr : "+pbk2);
    System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+pbk2);
    System.out.println("Length of addr : "+pbk2.length());
    System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
    System.out.println("-------------------------------------------------------------------\n");

    BigInteger transaction_id = new BigInteger("aaf62939216c3c6987756682a57cf83ea5a11536e4369a42358241e447c3dbe1", 16);
    TxIn tx_in = new TxIn(transaction_id.toByteArray(), 1, null, "test");
    
    byte[] out1_pkb_hash = PublicKey.toPublicKey(publicKey2).encode(true, true);
    ArrayList<Object> t = new ArrayList<Object>();
    ArrayList<ArrayList<Object>> temp = new  ArrayList<ArrayList<Object>>();
    t.add(118);
    temp.add(t);
    t = new ArrayList<Object>();
    t.add(169);
    temp.add(t);
    t = new ArrayList<Object>();
    for(byte by : out1_pkb_hash){
        t.add((byte)by);
    }
    temp.add(t);
    t = new ArrayList<Object>();
    t.add(136);
    temp.add(t);
    t = new ArrayList<Object>();
    t.add(172);
    temp.add(t);
    
    Script out1_script = new Script(temp);
    System.out.println("out1_script : "+bytesToHex(out1_script.encode()));

    byte[] out2_pkb_hash = PublicKey.toPublicKey(publicKey).encode(true, true);
    ArrayList<Object> t2 = new ArrayList<Object>();
    ArrayList<ArrayList<Object>> temp2 = new  ArrayList<ArrayList<Object>>();
    t2.add(118);
    temp2.add(t2);
    t2 = new ArrayList<Object>();
    t2.add(169);
    temp2.add(t2);
    t2 = new ArrayList<Object>();
    for(byte by : out2_pkb_hash){
        t2.add((byte)by);
    }
    // System.out.println(Arrays.toString(t.toArray()));
    temp2.add(t2);
    t2 = new ArrayList<Object>();
    t2.add(136);
    temp2.add(t2);
    t2 = new ArrayList<Object>();
    t2.add(172);
    temp2.add(t2);
    Script out2_script = new Script(temp2);
    System.out.println("out2_script : "+bytesToHex(out2_script.encode()));
    
    TxOut tx_out1 = new TxOut(5000, out1_script);
    TxOut tx_out2 = new TxOut(4750, out2_script);

    ArrayList<TxOut> out_scripts = new ArrayList<TxOut>();
    out_scripts.add(tx_out1);
    out_scripts.add(tx_out2);
    
    ArrayList<TxIn> tx_in_scripts = new ArrayList<TxIn>();
    tx_in_scripts.add(tx_in);

    Tx tx = new Tx(1, tx_in_scripts, out_scripts);

    ArrayList<Object> t3 = new ArrayList<Object>();
    ArrayList<ArrayList<Object>> temp3 = new  ArrayList<ArrayList<Object>>();
    t3.add(118);
    temp3.add(t3);
    t3 = new ArrayList<Object>();
    t3.add(169);
    temp3.add(t3);
    t3 = new ArrayList<Object>();
    for(byte by : out2_pkb_hash){
        t3.add((byte)by);
    }
    temp3.add(t3);
    t3 = new ArrayList<Object>();
    t3.add(136);
    temp3.add(t3);
    t3 = new ArrayList<Object>();
    t3.add(172);
    temp3.add(t3);

    Script source_script = new Script(temp3);
    System.out.println("recall out2_pkb_hash is just raw bytes of the hash of public_key: "+bytesToHex(out2_pkb_hash));
    System.out.println("source_script : "+bytesToHex(source_script.encode()));

    tx_in.setPrevScript(source_script);

    byte[] message = tx.encode(0);
    System.out.println("\nmessage : "+bytesToHex(message));
    System.out.println("-------------------------------------------------------------------\n");

    Signature sig = new Signature();
    sig = sig.sign(secretKey, message);
    System.out.println("\nSignature : \n" + sig);
    System.out.println("-------------------------------------------------------------------\n");

    byte[] sig_bytes = sig.encode();
    
    byte [] sig_bytes_and_type = new byte[sig_bytes.length+1];
    int i = 0;
    for(i = 0; i<sig_bytes.length; i++){
      sig_bytes_and_type[i] = sig_bytes[i];
    }
    sig_bytes_and_type[i] = (byte)0x01;

    byte[] pubkey_bytes = PublicKey.toPublicKey(publicKey).encode(true, false);

    ArrayList<ArrayList<Object>> par = new ArrayList<ArrayList<Object>>();
    t3 = new ArrayList<Object>();
    for(byte sbt : sig_bytes_and_type){
      t3.add(sbt);
    }
    par.add(t3);
    t3 = new ArrayList<Object>();
    for(byte sbt : pubkey_bytes){
      t3.add(sbt);
    }
    par.add(t3);

    Script script_sig = new Script(par);
    tx_in.setScript(script_sig);

    System.out.println(bytesToHex(tx.encode(-1)));
    System.out.println(tx.encode(-1).length);

    System.out.println("-------------------------------------------------------------------\n");
    // System.out.println(bytesToHex(tx.encode(-1)));
    System.out.println("id : "+tx.id());

    // Object re[] = PublicKey.gen_key_pair();
    // System.out.println(re[0]);
    // System.out.println(re[1]);
    // ParseBlockChain e = new ParseBlockChain();
    // e.get();

  
  }
}


// 0100000001b2364d6ba4cbfd3dad8d6dc8dde1095f959bac4ee4ee7c4b8ab99fc885503246010000006a473044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022072e4505d09e2bfe209a0c0b5e1aac1ca435159ec6f1ea563475e16eb250bf7e9012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0250c30000000000001976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac8cb90000000000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac00000000
// 010000000146325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2010000006a473044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022072e4505d09e2bfe209a0c0b5e1aac1ca435159ec6f1ea563475e16eb250bf7e9012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0250c30000000000001976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac8cb90000000000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac00000000

// 55eddf1c8ef552ef74945edd3b62b148a896e0015775153193e6b0657a6cb5c3
// 96de260bfb74be8adee650636a94abe9f6f2e3e67574111092aacae7f60c00ef

// 47304402205a002f19d40a32765829fbd7a568f42673cc71ca3bf9299c2cebe9ea08d746ee0220506fbd9f03d488e2c34a431b8973aab5687003960c8b54d5eaccc4d2fb97713e012103b2e02947f1c6beb1d588405a09a51f9b1bf9a5582e3292d4cd09861bc10ba5ef
// 010000000146325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b20100000069473044022046b9df85b5ee399291e32d21b5f7784632a2f64d6ab5931d96e6b2d98bfe32d00220143106fa5b4fe267aaed4ec6522c1a86a151b1ede3ec49b2b50f20bc3da8e37401200287de41a0d1520a709076f7de86509df879c98e71da6b87a2de10c991f6cd94ffffffff0288130000000000001976a9148510ed509407c47cca6c6dca08eea0535150683988ac8e120000000000001976a914a02ca15899fec6312a0578c7e27ecb50d6982a1688ac00000000