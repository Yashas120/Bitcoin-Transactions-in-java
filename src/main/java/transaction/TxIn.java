package transaction;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

class TxIn_helper extends helper{



    static byte[] encode_int(long sequence, int nbytes, String encoding){ 
        BigInteger bigInt = BigInteger.valueOf(sequence);      
        byte[] s = bigInt.toByteArray();
        byte[] out = new byte[nbytes];
        reverse(s);
        if(encoding == "little"){
            for(int ind=0; ind<nbytes; ind++){
                if(ind<s.length){
                    out[ind] = s[ind];
                    continue;
                }
                out[ind] = 0;
            }
        }
        else{
            for(int ind=0; ind < nbytes; ind++){
                if(ind < nbytes - s.length){
                    out[ind] = 0;
                    continue;
                }
                out[ind] = s[nbytes - ind - 1];
            }
        }
        return out;
    }

    static byte[] encode_int(BigInteger sequence, int nbytes, String encoding){ 
        BigInteger bigInt = sequence;     
        byte[] s1 = bigInt.toByteArray();
        int start_idx = 0;
        for(int i=0; i<s1.length; i++){
            if(s1[i] == (byte)0x0){
            continue;
            }
            else{
            start_idx = i;
            break;
            }
        }
        // System.out.println("Start Index : "+start_idx+" len : "+pt.length);
        // System.out.println("Txin PT : " + helper.bytesToHex(pt));
        byte []s = new byte[4];
      
        int idx = 0;
        for(int i=start_idx; i<s1.length; i++){
            s[idx++] = s1[i];
        }
        byte[] out = new byte[nbytes];
        reverse(s);
        if(encoding == "little"){
            for(int ind=0; ind<nbytes; ind++){
                if(ind<s.length){
                    out[ind] = s[ind];
                    continue;
                }
                out[ind] = 0;
            }
        }
        else{
            for(int ind=0; ind < nbytes; ind++){
                if(ind < nbytes - s.length){
                    out[ind] = 0;
                    continue;
                }
                out[ind] = s[nbytes - ind - 1];
            }
        }
        return out;
    }

    static byte[] encode_varint(int i) throws Exception{
    
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if(i < 0xfd){
            output.write(i);
            output.flush();
            return output.toByteArray();
        }
        else if (i < 0x10000){
            output.write(253);
            output.write(encode_int(i, 2,"little"));
            return output.toByteArray();
        }
        else if (i < 0x100000000l){
            output.write(254);
            output.write(encode_int(i, 4,"little"));
            return output.toByteArray();
        }
        else if (BigInteger.valueOf(i).compareTo(new BigInteger("10000000000000000",16)) == 1){
            output.write(255);
            output.write(encode_int(i, 8,"little"));
            return output.toByteArray();
        }
        else{
            throw new Exception(String.format("Integer too large: %d",i));
        }
    }


    // Dictionary OP_CODE_NAMES = new Hashtable();

}

public class TxIn{
    byte[] prev_tx;
    int prev_index;
    Script script_sig;
    BigInteger sequence; 
    String net;
    public Script prev_tx_script_pubkey;

    public TxIn(byte[] pt, int pi, Script ss, String net){
        int start_idx = 0;
        for(int i=0; i<pt.length; i++){
            if(pt[i] == (byte)0x0){
            continue;
            }
            else{
            start_idx = i;
            break;
            }
        }
        // System.out.println("Start Index : "+start_idx+" len : "+pt.length);
        // System.out.println("Txin PT : " + helper.bytesToHex(pt));
        this.prev_tx = new byte[32];
      
        int idx = 0;
        for(int i=start_idx; i<pt.length; i++){
            this.prev_tx[idx++] = pt[i];
        }
        // System.out.println();
        // System.out.println("Txin PT2 : " + helper.bytesToHex(this.prev_tx));

        this.prev_index = pi;
        this.script_sig = ss;
        this.sequence = new BigInteger("ffffffff",16);
        this.net = net;
    }

    public void setScript(Script sp){
        this.script_sig = sp;
    }

    public void setPrevScript(Script sp){
        this.prev_tx_script_pubkey = sp;
    }

    public byte[] encode(int script_override) throws Exception{
        List<Byte> out = new ArrayList<Byte>();
        // System.out.println("prev tx: " + helper.bytesToHex(this.prev_tx));
        // System.out.println("prev tx rev: " + helper.bytesToHex(helper.reverse(this.prev_tx)));

        for(byte p : TxIn_helper.reverse(this.prev_tx)){
            out.add(p);
        }
        for(byte p : TxIn_helper.encode_int(this.prev_index,4,"little")){
            out.add(p);
        }

        if(script_override == 3){
            for(byte p : this.script_sig.encode()){
                out.add(p);
            }
        }
        else if(script_override == 1){
            // Tx tx = new Tx();

            // Check this for the TxFetcher

            // tx = TxFetcher.fetch(helper.bytesToHex(this.prev_tx),this.net);
            // for(byte p : tx.tx_outs.get(this.prev_index).script_pubkey.encode()){
            //     out.add(p);
            // }
            for(byte p : this.prev_tx_script_pubkey.encode()){
                out.add(p);
            }

        }
        else if(script_override == 2){
            for(byte p: new Script().encode()){
                out.add(p);
            }
        }
        else{
            throw new Exception("script_override must be one of None|True|False\n");
        }
        
        for(byte p : TxIn_helper.encode_int(this.sequence,4,"little")){
            out.add(p);
        }
        byte[] bytes = new byte[out.size()];
            int j=0;
            for(Byte b: out.toArray(new Byte[0])) {
                bytes[j++] = b.byteValue();
            }
        return bytes;  
    }
}

// 0100000001cabe0b2f21c7da6a6b2554fec514839dbf7b4d34af3eba817b665132c8c6b1df010000006b483045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502207d9c0c49d5ab5608e09f5f1c7d9d42bc1570185978858c0fb05d226baf7676260121038419c0507a606ff1565b970ecbfca610110a2e3cdda41dacb84a33516321af62ffffffff02e8030000000000001976a9144878c417c70881794fc1f3233f36e3ae19bce9e888ac52030000000000001976a9148ecc46058bd0141a79375d2d9483bc8df627602688ac00000000
// 0100000001cabe0b2f21c7da6a6b2554fec514839dbf7b4d34af3eba817b665132c8c6b1df010000006b483045022100c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502207d9c0c49d5ab5608e09f5f1c7d9d42bc1570185978858c0fb05d226baf7676260121038419c0507a606ff1565b970ecbfca610110a2e3cdda41dacb84a33516321af62ffffffff02e8030000000000001976a9144878c417c70881794fc1f3233f36e3ae19bce9e888ac52030000000000001976a9148ecc46058bd0141a79375d2d9483bc8df627602688ac00000000

// b53b5ae756c1723f90e8b04f69eb6095b10573c2182a2168807be5d603daedfa
// b53b5ae756c1723f90e8b04f69eb6095b10573c2182a2168807be5d603daedfa