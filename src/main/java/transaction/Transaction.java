package transaction;

import hashing.Sha;
import hashing.Ripemd160;
import ecc.PublicKey;
import ecdsa.Signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.math.*;


class helper{


    public static String bytesToHexforDecode(byte[] byteArray, ByteOrder byteOrder) {
        final char[] lookup = new char[]{0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
         // our output size will be exactly 2x byte-array length
        final char[] buffer = new char[byteArray.length * 2];

        int index;
        for (int i = 0; i < byteArray.length; i++) {
            // for little endian we count from last to first
            index = (byteOrder == ByteOrder.BIG_ENDIAN) ? i : byteArray.length - i - 1;
            
            // extract the upper 4 bit and look up char (0-A)
            buffer[i << 1] =lookup[(byteArray[index] >> 4) & 0xF];
            // extract the lower 4 bit and look up char (0-A)
            buffer[(i << 1) + 1] = lookup[(byteArray[index] & 0xF)];
        }
        return new String(buffer);
    }
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    protected String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    static protected void reverse(byte[] array) {
        if (array == null) {
            return;
        }
        int i = 0;
        int j = array.length - 1;
        byte tmp;
        while (j > i) {
            tmp = array[j];
            array[j] = array[i];
            array[i] = tmp;
            j--;
            i++;
        }
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

    static protected long bytesToLongLittle(byte []arr){
        byte []conv = new byte[8];
        conv[0] = arr[0];
        conv[1] = arr[1];
        conv[2] = arr[2];
        conv[3] = arr[3];
        return ByteBuffer.wrap(conv).getLong();
    }

    static BigInteger decode_int(InputStream s, long nbytes, String encoding) throws IOException{
        byte[] inp = new byte[(int) nbytes];
        for(int i=0; i<nbytes; i++){
            inp[i] = (byte)s.read();
        }
        if(encoding == "little"){
            return new BigInteger(bytesToHexforDecode(inp, ByteOrder.LITTLE_ENDIAN),16);
        }
        else{
            return new BigInteger(bytesToHexforDecode(inp, ByteOrder.BIG_ENDIAN),16);
        }
    }

    static byte[] encode_int(int i, int nbytes, String encoding){ 
        BigInteger bigInt = BigInteger.valueOf(i);      
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

    static int decode_varint(InputStream s) throws IOException{
        BigInteger i = decode_int(s, 1,"little");
        if(i.equals(new BigInteger("fd")))
            return decode_int(s, 2,"little").intValue();
        else if (i.equals(new BigInteger("fe")))
            return decode_int(s, 4,"little").intValue();
                else if (i.equals(new BigInteger("ff")))
            return decode_int(s, 8,"little").intValue();
        else
            return i.intValue();
    }

    static byte[] encode_varint(int i) throws IOException{
    
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
        else if (i < BigInteger.valueOf(0x10000000000000000)){
            output.write(255);
            output.write(encode_int(i, 8,"little"));
            return output.toByteArray();
        }
        else{
            throw new Exception(String.format("integer too large: %d",i));
        }
    }


    // Dictionary OP_CODE_NAMES = new Hashtable();
    public static Map<Byte,String> OCN(){ 
        Map<Byte, String> OP_CODE_NAMES = new HashMap<>();

        OP_CODE_NAMES.put((byte) 0,"OP_0");
        OP_CODE_NAMES.put((byte) 76,"OP_PUSHDATA1");
        OP_CODE_NAMES.put((byte) 77,"OP_PUSHDATA2");
        OP_CODE_NAMES.put((byte) 78,"OP_PUSHDATA4");
        OP_CODE_NAMES.put((byte) 79,"OP_1NEGATE");
        OP_CODE_NAMES.put((byte) 81,"OP_1");
        OP_CODE_NAMES.put((byte) 82,"OP_2");
        OP_CODE_NAMES.put((byte) 83,"OP_3");
        OP_CODE_NAMES.put((byte) 84,"OP_4");
        OP_CODE_NAMES.put((byte) 85,"OP_5");
        OP_CODE_NAMES.put((byte) 86,"OP_6");
        OP_CODE_NAMES.put((byte) 87,"OP_7");
        OP_CODE_NAMES.put((byte) 88,"OP_8");
        OP_CODE_NAMES.put((byte) 89,"OP_9");
        OP_CODE_NAMES.put((byte) 90,"OP_10");
        OP_CODE_NAMES.put((byte) 91,"OP_11");
        OP_CODE_NAMES.put((byte) 92,"OP_12");
        OP_CODE_NAMES.put((byte) 93,"OP_13");
        OP_CODE_NAMES.put((byte) 94,"OP_14");
        OP_CODE_NAMES.put((byte) 95,"OP_15");
        OP_CODE_NAMES.put((byte) 96,"OP_16");
        OP_CODE_NAMES.put((byte) 97,"OP_NOP");
        OP_CODE_NAMES.put((byte) 99,"OP_IF");
        OP_CODE_NAMES.put((byte) 100, "OP_NOTIF");
        OP_CODE_NAMES.put((byte) 103, "OP_ELSE");
        OP_CODE_NAMES.put((byte) 104, "OP_ENDIF");
        OP_CODE_NAMES.put((byte) 105 ,"OP_VERIFY");
        OP_CODE_NAMES.put((byte) 106 ,"OP_RETURN");
        OP_CODE_NAMES.put((byte) 107 ,"OP_TOALTSTACK");
        OP_CODE_NAMES.put((byte) 108 ,"OP_FROMALTSTACK");
        OP_CODE_NAMES.put((byte) 109 ,"OP_2DROP");
        OP_CODE_NAMES.put((byte) 110 ,"OP_2DUP");
        OP_CODE_NAMES.put((byte) 111 ,"OP_3DUP");
        OP_CODE_NAMES.put((byte) 112 ,"OP_2OVER");
        OP_CODE_NAMES.put((byte) 113 ,"OP_2ROT");
        OP_CODE_NAMES.put((byte) 114 ,"OP_2SWAP");
        OP_CODE_NAMES.put((byte) 115 ,"OP_IFDUP");
        OP_CODE_NAMES.put((byte) 116 ,"OP_DEPTH");
        OP_CODE_NAMES.put((byte) 117 ,"OP_DROP");
        OP_CODE_NAMES.put((byte) 118 ,"OP_DUP");
        OP_CODE_NAMES.put((byte) 119 ,"OP_NIP");
        OP_CODE_NAMES.put((byte) 120 ,"OP_OVER");
        OP_CODE_NAMES.put((byte) 121 ,"OP_PICK");
        OP_CODE_NAMES.put((byte) 122 ,"OP_ROLL");
        OP_CODE_NAMES.put((byte) 123 ,"OP_ROT");
        OP_CODE_NAMES.put((byte) 124 ,"OP_SWAP");
        OP_CODE_NAMES.put((byte) 125 ,"OP_TUCK");
        OP_CODE_NAMES.put((byte) 130 ,"OP_SIZE");
        OP_CODE_NAMES.put((byte) 135 ,"OP_EQUAL");
        OP_CODE_NAMES.put((byte) 136 ,"OP_EQUALVERIFY");
        OP_CODE_NAMES.put((byte) 139 ,"OP_1ADD");
        OP_CODE_NAMES.put((byte) 140 ,"OP_1SUB");
        OP_CODE_NAMES.put((byte) 143 ,"OP_NEGATE");
        OP_CODE_NAMES.put((byte) 144 ,"OP_ABS");
        OP_CODE_NAMES.put((byte) 145 ,"OP_NOT");
        OP_CODE_NAMES.put((byte) 146 ,"OP_0NOTEQUAL");
        OP_CODE_NAMES.put((byte) 147 ,"OP_ADD");
        OP_CODE_NAMES.put((byte) 148 ,"OP_SUB");
        OP_CODE_NAMES.put((byte) 154 ,"OP_BOOLAND");
        OP_CODE_NAMES.put((byte) 155 ,"OP_BOOLOR");
        OP_CODE_NAMES.put((byte) 156 ,"OP_NUMEQUAL");
        OP_CODE_NAMES.put((byte) 157 ,"OP_NUMEQUALVERIFY");
        OP_CODE_NAMES.put((byte) 158 ,"OP_NUMNOTEQUAL");
        OP_CODE_NAMES.put((byte) 159 ,"OP_LESSTHAN");
        OP_CODE_NAMES.put((byte) 160 ,"OP_GREATERTHAN");
        OP_CODE_NAMES.put((byte) 161 ,"OP_LESSTHANOREQUAL");
        OP_CODE_NAMES.put((byte) 162 ,"OP_GREATERTHANOREQUAL");
        OP_CODE_NAMES.put((byte) 163 ,"OP_MIN");
        OP_CODE_NAMES.put((byte) 164 ,"OP_MAX");
        OP_CODE_NAMES.put((byte) 165 ,"OP_WITHIN");
        OP_CODE_NAMES.put((byte) 166 ,"OP_RIPEMD160");
        OP_CODE_NAMES.put((byte) 167 ,"OP_SHA1");
        OP_CODE_NAMES.put((byte) 168 ,"OP_SHA256");
        OP_CODE_NAMES.put((byte) 169 ,"OP_HASH160");
        OP_CODE_NAMES.put((byte) 170 ,"OP_HASH256");
        OP_CODE_NAMES.put((byte) 171 ,"OP_CODESEPARATOR");
        OP_CODE_NAMES.put((byte) 172 ,"OP_CHECKSIG");
        OP_CODE_NAMES.put((byte) 173 ,"OP_CHECKSIGVERIFY");
        OP_CODE_NAMES.put((byte) 174 ,"OP_CHECKMULTISIG");
        OP_CODE_NAMES.put((byte) 175 ,"OP_CHECKMULTISIGVERIFY");
        OP_CODE_NAMES.put((byte) 176 ,"OP_NOP1");
        OP_CODE_NAMES.put((byte) 177 ,"OP_CHECKLOCKTIMEVERIFY");
        OP_CODE_NAMES.put((byte) 178 ,"OP_CHECKSEQUENCEVERIFY");
        OP_CODE_NAMES.put((byte) 179 ,"OP_NOP4");
        OP_CODE_NAMES.put((byte) 180 ,"OP_NOP5");
        OP_CODE_NAMES.put((byte) 181 ,"OP_NOP6");
        OP_CODE_NAMES.put((byte) 182 ,"OP_NOP7");
        OP_CODE_NAMES.put((byte) 183 ,"OP_NOP8");
        OP_CODE_NAMES.put((byte) 184 ,"OP_NOP9");
        OP_CODE_NAMES.put((byte) 185 ,"OP_NOP10");

        return OP_CODE_NAMES;
    }
}

class TxFetcher{
    static public Tx fetch(String tx_id, String net) throws Exception{
        tx_id = tx_id.toLowerCase();
        String txdb_dir = "txdb";
        Path currentPath = Paths.get(txdb_dir);
        currentPath.resolve(tx_id);
        String cache_file = currentPath.toString();

        // Cache transactions on disk so we're not stressing the generous API provider
        byte[] raw;
        if(Files.exists(currentPath)){
            raw = Files.readAllBytes(currentPath);
        }
        else{
            String url = "";
            if(net=="main"){
                url = String.format("https://blockstream.info/api/tx/%s/hex",tx_id );
            }
            else if(net=="test"){
                url = String.format("https://blockstream.info/testnet/api/tx/%s/hex",tx_id);
            }
            else{
                throw new Exception(String.format("%s is not a valid net type, should be  main|test",net));
            }
            // java.util.Scanner s = new java.util.Scanner(new java.net.URL(url).openStream());
            // String response = "";
            // response += s.useDelimiter("\\A").next();
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            BigInteger b = new BigInteger(response.body().strip(),16);
            raw = b.toByteArray();
            if(!Files.isDirectory(Paths.get(txdb_dir))){
                Files.createDirectories(Paths.get(txdb_dir));
                Files.write(Paths.get(cache_file), raw);
            }
        }
        Tx tx = new Tx();
        tx = tx.decode(tx,raw);
        return tx;
    }
}

    class Tx {
        protected int version;
        protected ArrayList<TxIn> tx_ins = new ArrayList<TxIn>();
        protected ArrayList<TxOut> tx_outs = new ArrayList<TxOut>();
        protected int locktime = 0;
        protected boolean segwit = false;
    
        public Tx decode(Tx cls, byte[] s){
            int ver = helper.decode_int(s,4,"little");
            boolean seg = false;
            int num_inputs = helper.decode_varint(s);
            if(num_inputs==0){
                num_inputs = helper.decode_varint(s);
                segwit = true;
            }
            ArrayList<TxIn> inputs = new ArrayList<TxIn>();
            for(int i=0;i < num_inputs; i++){
                inputs.add(inputs.get(0).decode(s));
            }
            int num_outputs = helper.decode_varint(s);
            ArrayList<TxOut> outputs = new ArrayList<TxOut>();
            for(int i=0; i<num_outputs; i++){
                outputs.add(TxOut.decode(s));
            }

            if(seg){
                for(TxIn tx_in : inputs){
                    int num_items = helper.decode_varint(s);
                    List<Byte> items = new ArrayList<Byte>();
                    for(int i=0; i<num_items; i++){
                        int item_len = helper.decode_varint(s);
                        if(item_len==0){
                            items.add(item_len,(byte) 0);
                        }
                        else{
                            for(int cp=0; cp<item_len; cp++){
                                items.add(s[cp]);
                            }
                        }
                    }
                    tx_in.witness = items;
                }
            }
            int lock = helper.decode_int(s,4,"little");
            cls.version = ver;
            cls.segwit = seg;
            cls.tx_ins = inputs;
            cls.tx_outs = outputs;
            cls.locktime = lock;
            return cls;


        }

        public byte[] encode(boolean force_legacy, int sig_index){
            List<Byte> out = new ArrayList<Byte>();
            // Encode metadata
            byte[] temp = helper.encode_int(this.version,4,"little");
            for(int i=0; i<temp.length; i++){
                out.add(temp[i]);
            }
            if(this.segwit && !force_legacy){
                out.add((byte) 0);
                out.add((byte)1);
            }
            // Encode Inputs
            temp = helper.encode_varint(this.tx_ins.size());
            for(int i=0; i<temp.length; i++){
                out.add(temp[i]);
            }
            if(sig_index == -1){
                for(TxIn tx_in : this.tx_ins){
                    out.add(tx_in.encode(1));
                }
            }
            else{
                ListIterator<TxIn> lt = this.tx_ins.listIterator();
                while(lt.hasNext()){
                    out.add(lt.next().encode((sig_index==lt.nextIndex())));
                }
            }
            // Encode outputs
            temp = helper.encode_varint(this.tx_outs.size());
            for(int i=0; i<temp.length; i++){
                out.add(temp[i]);
            }
            for(TxOut tx_out : this.tx_outs){
                out.add(tx_out.encode());
            }
            // Encode Witness
            if(this.segwit && !force_legacy){
                for(TxIn tx_in : this.tx_ins){
                    temp = helper.encode_varint(tx_in.witness.size());
                    for(int i=0; i<temp.length; i++){
                        out.add(temp[i]);
                    }
                    for(Byte item : tx_in.witness){
                        if(item instanceof Integer){

                        }
                    }
                }
            }
            // Encode Locktime
            out.addAll(helper.encode_int(this.locktime,4,"little"));
            // Encode Sig Index
            if(sig_index != -1){
                for(byte p : helper.encode_int(1,4,"little")){
                    out.add(p);
                }
            }
            byte[] bytes = new byte[out.size()];
            int j=0;
            for(Byte b: out.toArray(new Byte[0])) {
                bytes[j++] = b.byteValue();
            }
            return bytes;  
        }

        public String id(){
            Tx tx = new Tx();
            Sha sha = Sha.getSha();
            byte[] res = sha.sha256(sha.sha256(tx.encode(true, -1)));
            helper.reverse(res);
            return helper.bytesToHex(res);
        }

        public long fee(){
            long input_total = 0;
            long output_total = 0;
            for(TxIn tx_in : this.tx_ins){
                input_total += tx_in.value();
            }
            for(TxOut tx_out : this.tx_outs){
                output_total += tx_out.amount;
            }
            return input_total - output_total;
        }

        public boolean validate(Tx tx){
            if(tx.fee() < 0){
                return false;
            }
            ListIterator<TxIn> lt = tx.tx_ins.listIterator();
            while(lt.hasNext()){
               byte[] mod_tx_enc = tx.encode(false,lt.nextIndex());
               TxIn tx_in = lt.next();
               Script combined = tx_in.script_sig + tx_in.script_pubkey();
               boolean valid = combined.evaluate(mod_tx_enc);
               if(!valid){
                   return false;
               }
               return true;
            }
        }

        public boolean is_coinbase(){
            return ((this.tx_ins.size()==1) && (Arrays.equals(this.tx_ins.get(0).prev_tx,helper.hexStringToByteArray("00000000000000000000000000000000"))) && (this.tx_ins[0].prev_index == 0xffffffff));
        }

        public long coinbase_height(){
            if(this.is_coinbase())
                return helper.bytesToLongLittle(this.tx_ins.get(0).script_sig.cmds[0]);

        }
    }

class TxIn{
    byte[] prev_tx;
    int prev_index;
    Script script_sig = new Script();
    int sequence = 0xffffffff;
    List<Byte> witness = new ArrayList<Byte>();
    String net = "";

    public void decode(byte[] s){
        this.prev_tx = Arrays.copyOfRange(s, 0, 32);
        helper.reverse(prev_tx);
        this.prev_index = helper.decode_int(s,4,"little");
        this.script_sig = Script.decode(s);
        this.sequence = helper.decode_int(s,4,"little");
        // TxIn tx_in = new TxIn();
        // tx_in.
         
    }

    public byte[] encode(int script_override){
        List<Byte> out = new ArrayList<Byte>();
        helper.reverse(this.prev_tx);
        for(byte p : this.prev_tx){
            out.add(p);
        }
        for(byte p : helper.encode_int(this.prev_index,4,"little")){
            out.add(p);
        }

        if(script_override == 3){
            for(byte p : this.script_sig.encode()){
                out.add(p);
            }
        }
        else if(script_override == 1){
            Tx tx = new Tx();
            tx = TxFetcher.fetch(helper.bytesToHex(this.prev_tx),this.net);
            for(byte p : tx.tx_outs.get(this.prev_index).script_pubkey.encode()){
                out.add(p);
            }
        }
        else if(script_override == 2){
            for(byte p: Script(new byte[0]).encode()){
                out.add(p);
            }
        }
        else{
            throw new Exception("script_override must be one of None|True|False\n");
        }
        for(byte p : helper.encode_int(this.sequence,4,"little")){
            out.add(p);
        }
        byte[] bytes = new byte[out.size()];
            int j=0;
            for(Byte b: out.toArray(new Byte[0])) {
                bytes[j++] = b.byteValue();
            }
        return bytes;  
    }

    public int value() throws Exception{
        Tx tx = new Tx();
        tx = TxFetcher.fetch(helper.bytesToHex(this.prev_tx),this.net);
        return tx.tx_outs.get(this.prev_index).amount;
    }

    public Script script_pubkey() throws Exception{
        Tx tx = new Tx();
        tx = TxFetcher.fetch(helper.bytesToHex(this.prev_tx),this.net);
        return tx.tx_outs.get(this.prev_index).script_pubkey;
    }

}


class TxOut{
    protected int amount = 0;
    protected Script script_pubkey = new Script();

    public static TxOut decode(byte[] s){
        int amt = helper.decode_int(s, 8, "little");
        Script spubkey = Script.decode(s);
        TxOut tx_out = new TxOut();
        tx_out.amount = amt;
        tx_out.script_pubkey = spubkey;
        return tx_out;
    }

    public byte[] encode(){
        ArrayList<Byte> out = new ArrayList<Byte>();
        for(byte p : helper.encode_int(this.amount, 8, "little")){
                out.add(p);
        }
        for(byte p : this.script_pubkey.encode()){
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

class Script{
    ArrayList<ArrayList<Object>> cmds = new ArrayList<ArrayList<Object>>();

    private static String repr_int(int cmd){
        Map<Byte, String> OP_CODE_NAMES = helper.OCN();
        return OP_CODE_NAMES.getOrDefault(cmd,String.format("OP_[%d]",cmd));
    }

    private static String repr_bytes(byte cmd){
        return Integer.toHexString(cmd);
    }

    public String repr(){
        String res = "";
        for(Object p : this.cmds){
            if(p instanceof Integer){
                res += Script.repr_int((int)p);
            }
            else{
                res += Script.repr_bytes((byte)p);
            }
        }
        return res;
    }

    public Script decode(byte[] s) throws Exception{
        InputStream stream = new ByteArrayInputStream(s);
        Script cls = new Script();
        int length = helper.decode_varint(s);
        ArrayList<Object> cmd = new ArrayList<Object>();
        int count = 0;
        int current;
        while(count < length){
           current = stream.read();
           count ++;
           if (1 <= current && current <= 75){
                // Elements of size [1,75] bytes
                for(int i=0; i<current; i++){
                    cmd.add(stream.read());
                }
                count += current;
           }
           else if( current == 76){
                // op_pushdata1: elements of size [76, 255] bytes
                int data_length = helper.decode_int(s,1,"little");
                for(int i=0; i<data_length; i++){
                    cmd.add(stream.read());
                }
                count += data_length + 1;
           }
           else if(current == 77){
                // op_pushdata2: elements of size [256-520] bytes
                int data_length = helper.decode_int(s,2,"little");
                for(int i=0; i<data_length; i++){
                    cmd.add(stream.read());
                }   
                count += data_length + 2;
           }
           else{
               for(int i=0; i<current; i++){
                   cmd.add(stream.read());
               }
           }
        }
        if (count != length){
            throw new Exception("Parsing script failed");
        }
        cls.cmds.add(cmd);
        return cls;
    }

    public byte[] encode() throws Exception{
        ArrayList<Byte> out = new ArrayList<Byte>();
        for(ArrayList<Object> cmd : this.cmds){
            int length = cmd.size();
            if(cmd.get(0) instanceof Integer && length == 1){
                for(byte i : helper.encode_int((int)cmd.get(0),1,"little")){
                    out.add(i);
                }
            }
            else{
                if(length < 75){
                    for(byte i : helper.encode_int(length,1,"little")){
                        out.add(i);
                    }
                }
                else if(76 <= length && length <=255){
                    // pushdata1
                    for(byte i : helper.encode_int(76,1,"little")){
                        out.add(i);
                    }
                    for(byte i : helper.encode_int(length,1,"little")){
                        out.add(i);
                    }
                }
                else if(256 <= length && length <=520){
                    // pushdata2
                    for(byte i : helper.encode_int(77,1,"little")){
                        out.add(i);
                    }
                    for(byte i : helper.encode_int(length,2,"little")){
                        out.add(i);
                    }
                }
                else{
                    throw new Exception(String.format("cmd of length %d bytes is too long",length));
                }
            }
            for(Object i :cmd){
                out.add((byte)i);
            }
        }
        int ind = 0;
       for(byte p: helper.encode_varint(out.size())){
           out.add(ind++,p);
       }
       byte[] bytes = new byte[out.size()];
            int j=0;
            for(Byte b: out.toArray(new Byte[0])) {
                bytes[j++] = b.byteValue();
            }
        return bytes;
    }

    
}
