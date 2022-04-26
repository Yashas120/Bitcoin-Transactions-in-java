package bitcoin;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.*;

import ecc.Curve;
import ecc.Point;
import ecc.Generator;
import ecc.PublicKey;
import transaction.TxIn;
import transaction.TxOut;
import transaction.Script;
import transaction.Tx;
import ecdsa.Signature;
import dashboard.Wallet;

public class CLI {

    public static final String ANSI_CYAN = "\u001B[36m";
    public static final String ANSI_BLACK = "\u001B[30m";
    public static final String ANSI_RED = "\u001B[31m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ANSI_WHITE = "\u001B[37m";
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_RED_BACKGROUND = "\u001B[41m";
    public static final String ANSI_GREEN_BACKGROUND = "\u001B[42m";
    public static final String ANSI_YELLOW_BACKGROUND = "\u001B[43m";
    public static final String ANSI_BLUE_BACKGROUND = "\u001B[44m";
    public static final String ANSI_PURPLE_BACKGROUND = "\u001B[45m";
    public static final String ANSI_CYAN_BACKGROUND = "\u001B[46m";
    public static final String ANSI_WHITE_BACKGROUND = "\u001B[47m";

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
    public static void main(String[] args) throws Exception{
        
        Scanner sc = new Scanner(System.in);

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
        
        Wallet W1;
        boolean flag;
        String W1_name;
        String W1_sk;
        do{
            System.out.println("Enter the Name of the Wallet : ");
            W1_name = sc.nextLine();
            System.out.println("Enter the Secret Key of the Wallet : ");
            W1_sk = sc.nextLine();
            startTime = System.nanoTime();
            W1 = new Wallet(W1_name, W1_sk);
            endTime = System.nanoTime();
            flag = W1.newWallet();
            flag = !flag;
            if(flag){
                System.out.println("Enter a new Unique Wallet");
            }
        }while(flag);
        
        duration = (endTime - startTime);
        System.out.println(ANSI_GREEN + String.format("\nBitcoin addr of Wallet %s : ",W1_name)+ ANSI_PURPLE + W1.addr + ANSI_RESET);
        System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+W1.addr);
        System.out.println("Length of addr : "+W1.addr.length());
        System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
        System.out.println("-------------------------------------------------------------------");

        // String secretKey_string = "chinna";
        // String secretKey_string = "vishal";
        // BigInteger secretKey = new BigInteger(toHex(W1_sk),16);
        // System.out.println(secretKey);
        // startTime = System.nanoTime();
        // Point publicKey = G.multiply(secretKey);
        // endTime = System.nanoTime();
        // duration = (endTime - startTime);
        // System.out.println("Secret Key : "+W1_sk);
        // System.out.println("Public Key : \nx : "+publicKey.x+"\ny : "+publicKey.y);
        // System.out.println("Public Key generated is on curve : \033[92m" + publicKey.verify_on_curve()+"\033[0m");
        // System.out.println("Time : "+duration/1000000+" ms");
        // System.out.println("----------------------------------------------------------------------");

        System.out.println("Enter the Name of the Second Wallet : ");
        String W2_name = sc.nextLine();
        System.out.println("Enter the Secret Key of the Second Wallet : ");
        String W2_sk = sc.nextLine();
        startTime = System.nanoTime();
        Wallet W2 = new Wallet(W2_name, W2_sk);
        endTime = System.nanoTime();

        duration = (endTime - startTime);
        System.out.println(ANSI_GREEN + String.format("\nBitcoin addr of Wallet %s : ",W2_name)+ ANSI_PURPLE + W2.addr + ANSI_RESET);
        System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+W2.addr);
        System.out.println("Length of addr : "+W2.addr.length());
        System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
        System.out.println("-------------------------------------------------------------------");

        // String secretKey_string2 = "munna";
        // BigInteger secretKey2 = new BigInteger(toHex(W2_sk),16);
        // System.out.println(secretKey2);
        // startTime = System.nanoTime();
        // Point publicKey2 = G.multiply(secretKey2);
        // endTime = System.nanoTime();
        // duration = (endTime - startTime);
        // System.out.println("Secret Key : "+W2_sk);
        // System.out.println("Public Key : \nx : "+publicKey2.x+"\ny : "+publicKey2.y);
        // System.out.println("Public Key generated is on curve : \033[92m" + publicKey2.verify_on_curve()+"\033[0m");
        // System.out.println("Time : "+duration/1000000+" ms");
        // System.out.println("-------------------------------------------------------------------");

        // startTime = System.nanoTime();
        // String pbk1 = PublicKey.toPublicKey(publicKey).address("test", true);
        // endTime = System.nanoTime();
        // duration = (endTime - startTime);
        
        // System.out.println("\nBitcoin addr : "+pbk1);
        // System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+pbk1);
        // System.out.println("Length of addr : "+pbk1.length());
        // System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
        // System.out.println("-------------------------------------------------------------------");

        // startTime = System.nanoTime();
        // String pbk2 = PublicKey.toPublicKey(publicKey2).address("test", true);
        // endTime = System.nanoTime();
        // duration = (endTime - startTime);
        
        // System.out.println("\nBitcoin addr : "+pbk2);
        // System.out.println("Link : https://www.blockchain.com/btc-testnet/address/"+pbk2);
        // System.out.println("Length of addr : "+pbk2.length());
        // System.out.println("Time Taken to Generate : "+duration/1000000+" ms");
        // System.out.println("-------------------------------------------------------------------\n");

        sc.next();

        BigInteger transaction_id = new BigInteger(W1.latestTx(), 16);

        TxIn tx_in = new TxIn(transaction_id.toByteArray(), 1, null, "test");
        
        byte[] out1_pkb_hash = PublicKey.toPublicKey(W2.publicKey).encode(true, true);
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

        byte[] out2_pkb_hash = PublicKey.toPublicKey(W1.publicKey).encode(true, true);
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

        temp2.add(t2);
        t2 = new ArrayList<Object>();
        t2.add(136);
        temp2.add(t2);
        t2 = new ArrayList<Object>();
        t2.add(172);
        temp2.add(t2);
        Script out2_script = new Script(temp2);
        System.out.println("out2_script : "+bytesToHex(out2_script.encode()));
        
        TxOut tx_out1 = new TxOut(1000, out1_script);
        TxOut tx_out2 = new TxOut(850, out2_script);

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
        sig = sig.sign(W1.secretKeyInt, message);
        System.out.println("\nSignature : \n" + sig);
        System.out.println("-------------------------------------------------------------------\n");

        byte[] sig_bytes = sig.encode();
        
        byte [] sig_bytes_and_type = new byte[sig_bytes.length+1];
        int i = 0;
        for(i = 0; i<sig_bytes.length; i++){
        sig_bytes_and_type[i] = sig_bytes[i];
        }
        sig_bytes_and_type[i] = (byte)0x01;

        byte[] pubkey_bytes = PublicKey.toPublicKey(W1.publicKey).encode(true, false);

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

        System.out.println(ANSI_GREEN + "Final Message Broadcasted : \n" + ANSI_GREEN_BACKGROUND + ANSI_WHITE + bytesToHex(tx.encode(-1)) + ANSI_RESET);
        System.out.println("Length of the Message Broadcasted : " + tx.encode(-1).length);

        W1.txBroadcast(bytesToHex(tx.encode(-1)));

        System.out.println("-------------------------------------------------------------------\n");
        System.out.println("id : "+tx.id());


  
    }
}
