import org.junit.Assert
import org.junit.jupiter.api.Assertions.*
import java.math.BigInteger

internal class ECDHSTest {

    @org.junit.jupiter.api.Test
    fun createSharedSecret() {
        val alice = ECDHS()
        val bob = ECDHS()

        val aliceSecret = alice.CreateSharedSecret(bob.pubKey)
        val bobSecret = bob.CreateSharedSecret(alice.pubKey)

        Assert.assertTrue(aliceSecret == bobSecret)
    }

    @org.junit.jupiter.api.Test
    fun getSignature() {
        val alice = ECDHS()
        val bob = ECDHS()

        val aliceSignature = alice.GetSignature("Test")
        val bobSignature = bob.GetSignature("Test")

        Assert.assertTrue(aliceSignature != bobSignature)
    }

    @org.junit.jupiter.api.Test
    fun validateSignature() {
        val alice = ECDHS()
        val bob = ECDHS()
        val clemens = ECDHS()

        val aliceSignature = alice.GetSignature("Test")
        val bobSignature = bob.GetSignature("Test")

        Assert.assertTrue(bob.ValidateSignature("Test", alice.pubKey, aliceSignature))
        Assert.assertTrue(alice.ValidateSignature("Test", bob.pubKey, bobSignature))

        Assert.assertFalse(alice.ValidateSignature("Test", clemens.pubKey, bobSignature))
        Assert.assertFalse(bob.ValidateSignature("Test2", alice.pubKey, aliceSignature))
        Assert.assertFalse(alice.ValidateSignature("Test2", bob.pubKey, bobSignature))
    }

    @org.junit.jupiter.api.Test
    fun HKDF(){
        val alice = ECDHS()
        val bob = ECDHS()

        val sharedSecret = alice.CreateSharedSecret(bob.pubKey)

        val aliceHKDF = alice.HKDF(256.0, sharedSecret.toByteArray(), ByteArray(10), ByteArray(0))
        val bobHKDF = bob.HKDF(256.0, sharedSecret.toByteArray(), ByteArray(10), ByteArray(0))

        Assert.assertTrue(aliceHKDF.contentEquals(bobHKDF))
    }
}