package transaction;

import java.io.*;
import java.math.BigInteger;
import java.util.*;

import hashing.Sha;

class Tx_helper extends helper{

    
    static byte[] encode_int(int i, int nbytes, String encoding){ 
        BigInteger bigInt = BigInteger.valueOf(i);      
        byte[] s = bigInt.toByteArray();
        byte[] out = new byte[nbytes];
        s = reverse(s);
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
        else if (BigInteger.valueOf(i).compareTo(new BigInteger("100000000",16)) == -1){
            output.write(254);
            output.write(encode_int(i, 4,"little"));
            return output.toByteArray();
        }
        else if (BigInteger.valueOf(i).compareTo(new BigInteger("10000000000000000",16)) == -1){
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

// class TxFetcher{
//     static public Tx fetch(String tx_id, String net) throws Exception{
//         tx_id = tx_id.toLowerCase();
//         String txdb_dir = "txdb";
//         Path currentPath = Paths.get(txdb_dir);
//         currentPath.resolve(tx_id);
//         String cache_file = currentPath.toString();

//         // Cache transactions on disk so we're not stressing the generous API provider
//         byte[] raw;
//         if(Files.exists(currentPath)){
//             raw = Files.readAllBytes(currentPath);
//         }
//         else{
//             String url = "";
//             if(net=="main"){
//                 url = String.format("https://blockstream.info/api/tx/%s/hex",tx_id );
//             }
//             else if(net=="test"){
//                 url = String.format("https://blockstream.info/testnet/api/tx/%s/hex",tx_id);
//             }
//             else{
//                 throw new Exception(String.format("%s is not a valid net type, should be  main|test",net));
//             }

//             HttpClient client = HttpClient.newHttpClient();
//             HttpRequest request = HttpRequest.newBuilder()
//                 .uri(URI.create(url))
//                 .build();
//             HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
//             BigInteger b = new BigInteger(response.body().strip(),16);
//             raw = b.toByteArray();
//             if(!Files.isDirectory(Paths.get(txdb_dir))){
//                 Files.createDirectories(Paths.get(txdb_dir));
//                 Files.write(Paths.get(cache_file), raw);
//             }
//         }
//         Tx tx = new Tx();
//         tx = tx.decode(tx,raw);
//         return tx;
//     }
// }

public class Tx {
    public int version;
    public ArrayList<TxIn> tx_ins;
    public ArrayList<TxOut> tx_outs;
    public int locktime;

    public Tx(int v, ArrayList<TxIn> ti, ArrayList<TxOut> to){
        this.version = v;
        this.tx_ins = ti;
        this.tx_outs = to;
        this.locktime = 0;
    }

    public String id() throws Exception{
        Sha sha = Sha.getSha();
        byte [] tx_encode = this.encode(-1);
        // System.out.println("in id tx_encode : "+Tx_helper.bytesToHex(tx_encode));
        byte[] res = sha.sha256(sha.sha256(this.encode(-1)));

        return Tx_helper.bytesToHex(Tx_helper.reverse(res));
    }

    public byte[] encode(int sig_index) throws Exception{
        // if(!(sig_index > -1)){
        //     sig_index = -1;
        // }
        List<Byte> out = new ArrayList<Byte>();
        // Encode metadata
        byte[] temp = Tx_helper.encode_int(this.version,4,"little");
        for(byte b : temp){
            out.add(b);
        }
        // System.out.println(Tx_helper.bytesToHex(temp));

        // Encode Inputs
        temp = Tx_helper.encode_varint(this.tx_ins.size());

        for(byte b : temp){
            out.add(b);
        }

        if(sig_index == -1){
            for(TxIn tx_in : this.tx_ins){
                for(byte b : tx_in.encode(3)){
                    out.add(b);
                }
                // System.out.println("TX Script_SIG 0");
                // System.out.println(Tx_helper.bytesToHex(tx_in.encode(3)));

            }

        }
        else{
            int counter = 0;
            for (TxIn script: this.tx_ins){
                int sig_idx = sig_index==counter ? 1 : 2;
                byte[] t = script.encode(sig_idx);
                for (byte b : t){
                    out.add(b);
                }
                // System.out.println("TX Script_SIG");
                // System.out.println(Tx_helper.bytesToHex(script.encode(sig_idx)));
                // System.out.println("sig_index!=-1 : "+Tx_helper.bytesToHex(t));
                counter++;
            }
            // for (int i =0; i<this.tx_ins.size(); i++){
            //     System.out.println("tx_ins : "+ this.tx_ins.get(i).prev_tx_script_pubkey);
            // }
            // ListIterator<TxIn> lt = this.tx_ins.listIterator();
            // while(lt.hasNext()){
            //     byte[] t = lt.next().encode((sig_index==lt.nextIndex())?1:2);
            //     for(byte b : t){
            //         out.add(b);
            //     }
            //     System.out.println("sig_index!=-1 : "+Tx_helper.bytesToHex(t));
            // }
            
        }
        // Encode outputs
        temp = Tx_helper.encode_varint(this.tx_outs.size());
        for(byte b : temp){
            out.add(b);
        }
        // System.out.println(Tx_helper.bytesToHex(temp));
        for(TxOut tx_out : this.tx_outs){
            for(byte b : tx_out.encode()){
                out.add(b);
            }
        //  System.out.println(Tx_helper.bytesToHex(temp));

        }
        // Encode Locktime
        for(byte b : Tx_helper.encode_int(this.locktime,4,"little")){
            out.add(b);
        }
        // System.out.println(Tx_helper.bytesToHex(Tx_helper.encode_int(this.locktime,4,"little")));

        // Encode Sig Index
        if(sig_index != -1){
            for(byte b : Tx_helper.encode_int(1,4,"little")){
                out.add(b);
            }
        }
        // System.out.println(Tx_helper.bytesToHex(Tx_helper.encode_int(1,4,"little")));
        
        byte[] bytes = new byte[out.size()];
        int j=0;
        for(Byte b: out.toArray(new Byte[0])) {
            bytes[j++] = b.byteValue();
        }
        return bytes;  
    }
}

// 010000000146325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2010000006a473044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022072e4505d09e2bfe209a0c0b5e1aac1ca435159ec6f1ea563475e16eb250bf7e9012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0250c30000000000001976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac8cb90000000000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac00000000
// 010000000146325085c89fb98a4b7ceee44eac9b955f09e1ddc86d8dad3dfdcba46b4d36b2010000006a473044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022072e4505d09e2bfe209a0c0b5e1aac1ca435159ec6f1ea563475e16eb250bf7e9012103b9b554e25022c2ae549b0c30c18df0a8e0495223f627ae38df0992efb4779475ffffffff0250c30000000000001976a91475b0c9fc784ba2ea0839e3cdf2669495cac6707388ac8cb90000000000001976a9144b3518229b0d3554fe7cd3796ade632aff3069d888ac00000000