# Bitcoin

From scratch zero-dependency implementation of Bitcoin for educational purposes, including all of the under the hood crypto primitives such as SHA-256 and elliptic curves over finite fields math.

This repository provides a from scratch implementation of Bitcoin, more specifically the Bitcoin protocol. In this project, we build all the cypto primitive functions required for implementing the protocol. Primitive functions include SHA 256, Ripemd-160, Elliptical Cryptographic Curves.

After building all the necessary functions, we will create two unique wallet addresses using our own secret keys and execute a real transaction on the bitcoin test network.

## Generating Wallet Addresses

In this section we will see the procedure to generate a real bitcoin wallet address.

First up, we will initialize our elliptical curve parameters with the following values

```java
BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
BigInteger a = new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16);
BigInteger b = new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16);
BigInteger x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
BigInteger y = new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
```

These values are standard values that the bitcoin protocol uses to generate a new wallet address.

Now we will create Curve and Point classes. Curve class bascially initializes our ECC curve with the parameters a, b, and p. The point class defines the seed point on this ECC curve. All bitcoin wallet addresses start with this point.

```java
Curve bitcoinCurve = new Curve(p,a,b);
Point G = new Point(bitcoinCurve,x,y);
```

Our next step is to obtain a secret key from the user. The secret key will be used kind of like a password for generating the wallet address. The secret key will first be converted to integers. This integer will then be multiplied with the seed point `G` we defined above. This operation results in adding `G ` to itself `secret_key` number of times. The addition operation will be performed on the ECC curve and the result of the addition process is a new point on the curve with coordinates (x,y)

For simplicity, we will assume the `secret_key` to be `2`.

```java
int secret_key = 2;
Point pk = G.add(G);
```

If `secret_key` is `3` then,

```java
int secret_key = 3;
Point pk = G.add(G).add(G);
```

However this process becomes tedious when the secret_key is a very large value (which is usually the case in most real world secret keys). Hence to make this process easier, we will use additional algorithms that will make the process much faster.

```java
BigInteger secret_key = new BigInteger("1234567890");
Point pk = G.multiply(secret_key);
```

Note that any point obtained after multiplying the seed point with the secret key must lie on the curve defined by us. Otherwise this point cannot be used for generating wallet addresses.

To verify if our new point lies on the curve,

```java
System.out.println("Secret Key : "+secret_key);
System.out.println("Public Key : \nx : "+pk.x+"\ny : "+pk.y);
System.out.println("Public Key generated is on curve : \033[92m" + pk.verify_on_curve()+"\033[0m");
```

```bash
> Secret Key : 1234567890
  Public Key :
  x : 19635924277356798752105674083697999930996555344818160161847497917044432760610
  y : 21218882238660449272792211265489841951893738252848232230063147580786068364204
  Generated Point is on curve : true
```

Now lets generate a real bitcoin address by providing the secret key manually,

```java
String secret_key_string = "This is the bitcoin address of the first wallet.";
BigInteger secret_key = new BigInteger(toHex(secret_key_string), 16);
```

Printing the secret_key will result in the following output

```bash
> 12991558534057774220956985186119368258644532210348760637115131129936353298097675813900069943909894649963898250556462
```

Generating our wallet address and verifying if on curve.

```java
Point pk = G.multiply(secret_key);
System.out.println("Secret Key : "+secret_key_string);
System.out.println("Public Key : \nx : "+pk.x+"\ny : "+pk.y);
System.out.println("Public Key generated is on curve : \033[92m" + pk.verify_on_curve()+"\033[0m");
```

```bash
> Secret Key : This is the bitcoin address of the first wallet.
  Public Key :
  x : 29923686304727414546372867934731867300885153587267117101239909099742076575844
  y : 55225955892413022444173037737626668999635271360017664979805373003105507264653
  Public Key generated is on curve : true
```

```java
String wallet_address = PublicKey.toPublicKey(pk).address("test", true);
System.out.println("\nBitcoin addr : "+wallet_address);
System.out.println("Wallet Link : https://www.blockchain.com/btc-testnet/address/"+wallet_address);
```

```bash
> Bitcoin addr : mtuaNikUc84ASfDF4Xn7CBqVEF5Ufa4U3U
  Wallet Link : https://www.blockchain.com/btc-testnet/address/mtuaNikUc84ASfDF4Xn7CBqVEF5Ufa4U3U
```

We now have successfully generated our wallet address and the wallet is accessible in the link provided above. At the time of writing this, the wallet is completely clean. You may not find the same wallet to be clean in future as we will execute a transaction using this wallet.

Similarly, we will generate our second wallet address required for the transaction.

```java
String secret_key_string2 = "This is the bitcoin address of the second wallet.";
BigInteger secret_key2 = new BigInteger(toHex(secret_key_string2), 16);
Point pk2 = G.multiply(secret_key2);
String wallet_address2 = PublicKey.toPublicKey(pk2).address("test", true);
System.out.println("\nBitcoin addr : "+wallet_address2);
System.out.println("Wallet Link : https://www.blockchain.com/btc-testnet/address/"+wallet_address2);
```

```bash
> Bitcoin addr : mtPUdKsCLdtfknqpmS1PKzYVXg2XHPXfMA
  Wallet Link : https://www.blockchain.com/btc-testnet/address/mtPUdKsCLdtfknqpmS1PKzYVXg2XHPXfMA
```


## Build

Install maven on your systems. 

On macOS, if you have brew installed please type the following command in terminal

```bash
brew install maven
```

Go into project directory and type the following command to build the project

```bash
mvn package
```

## Run the Code

To execute the bitcoin code, execute the following command in terminal

```bash
java -jar target/bitcoin-0.1.0.jar
```

## Acknowledgement

Special thanks to T Vijay Prashant and Yashas KS for helping complete this project.
