package bitcoin;
import transaction.TxIn;
import transaction.TxOut;
import transaction.Script;
import transaction.Tx;

import java.math.BigInteger;
import java.util.ArrayList;

import ecc.Curve;
import ecc.Point;
import ecc.PublicKey;

public class test{
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
        BigInteger x1 = new BigInteger("83998262154709529558614902604110599582969848537757180553516367057821848015989", 16);
        BigInteger y1 = new BigInteger("37676469766173670826348691885774454391218658108212372128812329274086400588247", 16);
        BigInteger x2 = new BigInteger("70010837237584666034852528437623689803658776589997047576978119215393051139210", 16);
        BigInteger y2 = new BigInteger("35910266550486169026860404782843121421687961955681935571785539885177648410329", 16);
        BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    
        Curve bitcoinCurve = new Curve(p,a,b);
        Point public_key = new Point(bitcoinCurve,x1,y1);
        Point public_key2 = new Point(bitcoinCurve,x2,y2);

        byte[] out1_pkb_hash = PublicKey.toPublicKey(public_key2).encode(true,true);
        ArrayList<Object> t = new ArrayList<Object>();
        ArrayList<ArrayList<Object>> temp = new  ArrayList<ArrayList<Object>>();
        t.add((byte)118);
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(169);
        temp.add(t);
        t = new ArrayList<Object>();
        for(byte by : out1_pkb_hash){
            t.add(by);
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
        // the second output will go back to us
        byte[] out2_pkb_hash = PublicKey.toPublicKey(public_key).encode(true,true);
        temp = new  ArrayList<ArrayList<Object>>();
        t.add((byte)118);
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(169);
        temp.add(t);
        t = new ArrayList<Object>();
        for(byte by : out2_pkb_hash){
            t.add(by);
        }
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(136);
        temp.add(t);
        t = new ArrayList<Object>();
        t.add(172);
        temp.add(t);
        Script out2_script = new Script(temp);
        System.out.println(out2_script.encode());
        assert bytesToHex(out2_script.encode()).equals("1976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac");

        TxOut.setScript(tx_out1, out1_script);
        TxOut.setScript(tx_out2, out2_script);

        ArrayList<TxIn> ti = new ArrayList<TxIn>();
        ti.add(tx_in);

        ArrayList<TxOut> to = new ArrayList<TxOut>();
        to.add(tx_out1);
        to.add(tx_out2);
        Tx tx = new Tx(1,ti,to);


    }
}


