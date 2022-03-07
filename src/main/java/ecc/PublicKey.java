package ecc;

import hashing.Ripemd160;
import hashing.Sha;
// import hashing.Ripemd160;
import java.math.BigInteger;

public class PublicKey extends Point{  
  public PublicKey(Curve curve, BigInteger x, BigInteger y){
    super(curve, x, y);
  }

  public static PublicKey toPublicKey(Point pt){
    return new PublicKey(pt.ecc_curve, pt.x, pt.y);
  }

  // private static String print(byte[] bytes) {
  //   StringBuilder sb = new StringBuilder();
  //   sb.append("[ ");
  //   for (byte b : bytes) {
  //       sb.append(String.format("0x%04x ", b));
  //   }
  //   sb.append("]");
  //   return sb.toString();
  // }

  private static String bytesToHex(byte[] in) {
    final StringBuilder builder = new StringBuilder();
    for(byte b : in) {
        builder.append(String.format("%02x", 0xFF & b));
    }
    return builder.toString();
  }

  private byte[] encode(Boolean compressed, Boolean hash160){
    
    byte []pbk;
    if (compressed){
      BigInteger temp = new BigInteger("2");
      BigInteger zero = new BigInteger("0");
      
      byte prefix = this.y.mod(temp).equals(zero) ? (byte)0x02 : (byte)0x03;
      byte []xBytes = this.x.toByteArray();
      
      pbk = new byte[xBytes.length + 1];
      pbk[0] = prefix;
      int i = 1; 
      int bound = pbk.length - 8 + 1;
      
      while(i<bound){
        pbk[i] = xBytes[i-1];
        pbk[i+1] = xBytes[i];
        pbk[i+2] = xBytes[i+1];
        pbk[i+3] = xBytes[i+2];
        pbk[i+4] = xBytes[i+3];
        pbk[i+5] = xBytes[i+4];
        pbk[i+6] = xBytes[i+5];
        pbk[i+7] = xBytes[i+6];
        i+=8;
      }
      while(i<pbk.length){
        pbk[i] = xBytes[i-1];
        i++;
      }

    }
    else{
      byte []xBytes = this.x.toByteArray();
      byte []yBytes = this.y.toByteArray();

      pbk = new byte[xBytes.length + yBytes.length + 1];
      pbk[0] = (byte)0x04;

      int i = 1;
      int bound = xBytes.length - 8 + 1;
      while(i<bound){
        pbk[i] = xBytes[i-1];
        pbk[i+1] = xBytes[i];
        pbk[i+2] = xBytes[i+1];
        pbk[i+3] = xBytes[i+2];
        pbk[i+4] = xBytes[i+3];
        pbk[i+5] = xBytes[i+4];
        pbk[i+6] = xBytes[i+5];
        pbk[i+7] = xBytes[i+6];
        i+=8;
      }
      while(i<xBytes.length+1){
        pbk[i] = xBytes[i-1];
        i++;
      }
      bound = pbk.length - 8 + 1;
      int counter = 0;
      while(i<bound){
        pbk[i] = yBytes[counter];
        pbk[i+1] = yBytes[counter+1];
        pbk[i+2] = yBytes[counter+2];
        pbk[i+3] = yBytes[counter+3];
        pbk[i+4] = yBytes[counter+4];
        pbk[i+5] = yBytes[counter+5];
        pbk[i+6] = yBytes[counter+6];
        pbk[i+7] = yBytes[counter+7];
        i+=8;
        counter += 8;
      }
      while(i<pbk.length){
        pbk[i] = yBytes[counter-1];
        i++;
        counter++;
      }
    }
    if(hash160){
      Sha sha = new Sha();
      pbk = sha.sha256(pbk);
      Ripemd160 rip = new Ripemd160();
      pbk = rip.RMD(pbk);
      return pbk;
    }
    else{
      return pbk;
    }
  }

  private String base58Encode(byte[] byte_address){
    String byte_address_string = bytesToHex(byte_address);
    String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    assert byte_address.length == 25;
    
    BigInteger n = new BigInteger(byte_address_string, 16);
    
    String address = "";
    BigInteger zero = new BigInteger("0");
    BigInteger div = new BigInteger("58");
    
    while (!n.equals(zero)){
      BigInteger []result = n.divideAndRemainder(div);
      n = result[0];
      address += alphabet.charAt(result[1].intValue());
    }

    int zero_counter = byte_address.length;
    for(int i = 0; i<byte_address.length; i++){
      if (byte_address[i] == (byte)0x00){
        zero_counter-=1;
      }
    }

    int num_zeros = byte_address.length - zero_counter;
    String reversed_byte_address = new StringBuilder(address).reverse().toString();

    String return_address = "";
    for (int i = 0; i<num_zeros; i++){
      return_address += alphabet.charAt(0);
    }
    return_address += reversed_byte_address;

    return return_address;
  }

  public String address(String net, Boolean compressed){
    byte[] pbk_hash = encode(compressed, true); // make true when ripemd is implemented

    byte version = (byte)0x6f;
    
    if (net == "main"){
      version = (byte)0x00;
    }
    else if(net == "test"){
      version = (byte)0x6f;
    }
    else{
      System.out.println("Error : Only main or test expected but got net="+net);
      System.exit(1); // find a better way to do this
    }
    
    byte []version_pbk_hash = new byte[pbk_hash.length + 1];
    version_pbk_hash[0] = version;
    
    int i = 1;
    int bound = version_pbk_hash.length - 8 + 1;
    while(i<bound){
      version_pbk_hash[i] = pbk_hash[i-1];
      version_pbk_hash[i+1] = pbk_hash[i];
      version_pbk_hash[i+2] = pbk_hash[i+1];
      version_pbk_hash[i+3] = pbk_hash[i+2];
      version_pbk_hash[i+4] = pbk_hash[i+3];
      version_pbk_hash[i+5] = pbk_hash[i+4];
      version_pbk_hash[i+6] = pbk_hash[i+5];
      version_pbk_hash[i+7] = pbk_hash[i+6];
      i+=8;
    }
    while (i<version_pbk_hash.length){
      version_pbk_hash[i] = pbk_hash[i-1];
      i++;
    }

    Sha hash = new Sha();
    byte[] checksum = hash.sha256(hash.sha256(version_pbk_hash));
    byte [] byte_address = new byte[version_pbk_hash.length + 4];
    
    i = 0;
    bound = byte_address.length - 8 - 4 + 1;
    while (i<bound){
      byte_address[i] = version_pbk_hash[i];
      byte_address[i+1] = version_pbk_hash[i+1];
      byte_address[i+2] = version_pbk_hash[i+2];
      byte_address[i+3] = version_pbk_hash[i+3];
      byte_address[i+4] = version_pbk_hash[i+4];
      byte_address[i+5] = version_pbk_hash[i+5];
      byte_address[i+6] = version_pbk_hash[i+6];
      byte_address[i+7] = version_pbk_hash[i+7];
      i+=8;
    }
    while (i<byte_address.length-4){
      byte_address[i] = version_pbk_hash[i];
      i++;
    }

    byte_address[i] = checksum[0];
    byte_address[i+1] = checksum[1];
    byte_address[i+2] = checksum[2];
    byte_address[i+3] = checksum[3];

    String address = base58Encode(byte_address);
    return address;
  } 
}