package bitcoin;

import hashing.Sha;

public class App {

    public static void main(String[] args) throws Exception {
        Sha hash = new Sha();
        String str = "a longer message to make sure that a larger number of blocks works okay too";
        for(int i=0;i<14;i++){
            str += "a longer message to make sure that a larger number of blocks works okay too";
        }
        System.out.println(hash.sha256("aaaaa"));   
        System.out.println(hash.sha256("abc"));   
        System.out.println(hash.sha256("hello"));   
        System.out.println(hash.sha256(str));   
        // System.out.println(capitalSigmoid1(12)) ;
    }
}