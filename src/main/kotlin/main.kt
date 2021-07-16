fun main(args: Array<String>) {
    val alice = ECDHS()
    val bob = ECDHS()
    val clemens = ECDHS()

    val signed = alice.GetSignature("Test")
    val signedC = clemens.GetSignature("Test")
    println(bob.ValidateSignature("Test", clemens.pubKey, signed))
}