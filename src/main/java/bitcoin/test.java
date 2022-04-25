package bitcoin;
import transaction.TxIn;
import transaction.TxOut;
import transaction.Script;
import transaction.Tx;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;

import ecc.Curve;
import ecc.Point;
import ecc.PublicKey;

public class test{
    public static String toHex(String arg) {
        return String.format("%040x", new BigInteger(1, arg.getBytes(Charset.forName("UTF-8"))));
      }
    static protected byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    private static String bytesToHex(byte[] in) {
        final StringBuilder builder = new StringBuilder();
        for(byte b : in) {
            builder.append(String.format("%02x", 0xFF & b));
        }
        return builder.toString();
      }

    public static void main(String[] args) throws Exception {
        TxIn tx_in = new TxIn(hexStringToByteArray("46325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2"), 1, new Script(), " "); 
        TxOut tx_out1 = new TxOut(50000, new Script());
        TxOut tx_out2 = new TxOut(47500, new Script());
        BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
        BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
        BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
        BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
        BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
        // BigInteger x1 = new BigInteger("83998262154709529558614902604110599582969848537757180553516367057821848015989", 16);
        // BigInteger y1 = new BigInteger("37676469766173670826348691885774454391218658108212372128812329274086400588247", 16);
        // BigInteger x2 = new BigInteger("70010837237584666034852528437623689803658776589997047576978119215393051139210", 16);
        // BigInteger y2 = new BigInteger("35910266550486169026860404782843121421687961955681935571785539885177648410329", 16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    
        Curve bitcoinCurve = new Curve(p,a,b);
        Point G = new Point(bitcoinCurve,x,y);
        // Point public_key2 = new Point(bitcoinCurve,x2,y2);
        // PublicKey aa = PublicKey.toPublicKey(public_key2);
        String secretKey_string2 = "Andrej's Super Secret 2nd Wallet";
        BigInteger secretKey2 = new BigInteger(toHex(secretKey_string2),16);
        Point publicKey2 = G.multiply(secretKey2);
        System.out.println(PublicKey.toPublicKey(publicKey2).address("test", true));
        System.out.println("Secret Key : "+secretKey_string2);
        System.out.println("Public Key : \nx : "+publicKey2.x+"\ny : "+publicKey2.y);
        System.out.println("Public Key generated is on curve : \033[92m" + publicKey2.verify_on_curve()+"\033[0m");
        System.out.println("-------------------------------------------------------------------"); 
        byte[] out1_pkb_hash = PublicKey.toPublicKey(publicKey2).encode(true,true);
        // System.out.println(bytesToHex(out1_pkb_hash));
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
        System.out.println(bytesToHex(out1_script.encode()));
        assert bytesToHex(out1_script.encode()).equals("1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac");
        // 1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac
        // 1976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac
        // the second output will go back to us
        String secretKey_string = "Andrej is cool :P";
        BigInteger secretKey = new BigInteger(toHex(secretKey_string),16);
        Point publicKey1 = G.multiply(secretKey);
        System.out.println("Secret Key : "+secretKey_string);
        System.out.println("Public Key : \nx : "+publicKey1.x+"\ny : "+publicKey1.y);
        System.out.println("Public Key generated is on curve : \033[92m" + publicKey1.verify_on_curve()+"\033[0m");
        System.out.println("-------------------------------------------------------------------");
        byte[] out2_pkb_hash = PublicKey.toPublicKey(publicKey1).encode(true,true);
        temp = new  ArrayList<ArrayList<Object>>();
        t = new ArrayList<Object>();
        t.add(118);
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(169);
        temp.add(t);
        t = new ArrayList<Object>();
        for(byte by : out2_pkb_hash){
            t.add((byte)by);
        }
        // System.out.println(Arrays.toString(t.toArray()));
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(136);
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(172);
        temp.add(t);
        Script out2_script = new Script(temp);
        System.out.println(temp);
        assert bytesToHex(out2_script.encode()).equals("1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac");
        TxOut.setScript(tx_out1, out1_script);
        TxOut.setScript(tx_out2, out2_script);

        ArrayList<TxIn> ti = new ArrayList<TxIn>();
        ti.add(tx_in);

        ArrayList<TxOut> to = new ArrayList<TxOut>();
        to.add(tx_out1);
        to.add(tx_out2);
        Tx tx = new Tx(1,ti,to);
        byte[] message = tx.encode(true, 0);
        System.out.println(bytesToHex(message));



    }
}


