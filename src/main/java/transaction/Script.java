package transaction;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

class script_helper extends helper{

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
}

public class Script{
    ArrayList<ArrayList<Object>> cmds;

    public Script(ArrayList<ArrayList<Object>> cmd){
        this.cmds = cmd;
    }
    public Script(){
        this.cmds  = new ArrayList<ArrayList<Object>>();
    }
    public byte[] encode() throws Exception{
        ArrayList<Byte> out = new ArrayList<Byte>();

        for(ArrayList<Object> cmd : this.cmds){
            int length = cmd.size();
            // System.out.println(cmd.size());
            // System.out.println(cmd.get(0) instanceof Integer);
            // System.out.println(cmd.get(0));
            if((cmd.get(0) instanceof Integer) && length == 1){
                // It is an instance of int
                byte t[] = script_helper.encode_int((int)cmd.get(0),1,"little");
                for(byte i : t){
                    out.add(i);
                }
            }
            else if(length < 75 && cmd.get(0) instanceof Byte){
                // System.out.println(cmd.toString());
                    byte[] t = script_helper.encode_int(length,1,"little");
                    for(byte i : t){
                        out.add(i);
                    }
                    for(Object i : cmd.toArray()){
                        out.add((byte)i);
                    }
            }
            else{
                    throw new Exception(String.format("cmd of length %d bytes is too long",length));
                }
            // System.out.println(out.toString());
            
            }
        int ind = 0;
        for(byte p: script_helper.encode_varint(out.size())){
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
