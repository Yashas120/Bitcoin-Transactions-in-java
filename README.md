# OOAD-Project-Blockchain
From-scratch zero-dependency implementation of Bitcoin for educational purposes, including all of the under the hood crypto primitives such as SHA-256 and elliptic curves over finite fields math.

## Build

Install maven on your systems. 

On macOS, if you have brew installed please type the following command in terimanl

```bash
brew install maven
```

cd into project directory and type the following command to build the project

```bash
mvn package
```

## Run the Code

To execute the bitcoin code, execute the following command in terminal

```bash
java -jar target/bitcoin-0.1.0.jar
```

## Java problems
Fix for unsigned int -> long
beyond that use BigInteger
Modulo operator in java doesnt work for negetive numbers replace n % m by (((n % m) + m) % m) 
## References

[Maven Guide](https://spring.io/guides/gs/maven/)
