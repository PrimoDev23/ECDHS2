import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil


class ECDHS(val curve : Curve = Curve("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000007", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", "1")) {
    private val hash_length = 32.0

    private val privKey : BigInteger
    val pubKey : BigInteger

    init {
        privKey = getRandomBigIntegerFrom(curve.n)
        pubKey = privKey * curve.gx
    }

    fun CreateSharedSecret(secondKey: BigInteger): BigInteger {
        return privKey * secondKey
    }

    fun GetSignature(message : String) : Signature {
        //Get the hash of the message
        val z = getHashFromString(message)

        var k : BigInteger
        var r : BigInteger
        var s : BigInteger

        do{
            do{
                //Select a random integer between 1 and n - 1
                k = getRandomBigIntegerFrom(curve.n);

                //Calculate random point
                r = (k % curve.n) * (curve.gx % curve.n) % curve.n;
            }while(r == BigInteger.ZERO)

            s = ((k.modInverse(curve.n) % curve.n) * ((z % curve.n) + (r % curve.n) * (privKey % curve.n))) % curve.n;
        }while(s == BigInteger.ZERO)

        return Signature(r.toString(), s.toString())
    }

    fun ValidateSignature(message : String, pubKey : BigInteger, sign : Signature) : Boolean{
        val r = BigInteger(sign.r)
        val s = BigInteger(sign.s)

        //Check if both ints are inside the range of n
        if (r > BigInteger.ZERO && r < curve.n && s > BigInteger.ZERO && s < curve.n) {
            //Get the according hash for the string
            val z = getHashFromString(message)

            //Calculate modInverse of s
            val s1: BigInteger = s.modInverse(curve.n)

            //Get point r on curve
            val r1 = (z * s1 * curve.gx + r * s1 * pubKey) % curve.n

            //Check if given r and calculated r are the same
            return r1 == r
        }

        //Covers all cases for an invalid signature
        return false
    }

    fun HKDF(length : Double, ikm : ByteArray, salt : ByteArray, info : ByteArray) : ByteArray{
        val hash = getHMACSHA256(salt, ikm)
        var temp : ByteArray = ByteArray(0)
        var outputKey = ByteArray(0)
        for (i in 0..ceil(length / hash_length).toInt()){
            temp = getHMACSHA256(hash, temp + info + ByteArray(1 + i))
            outputKey += temp
        }
        return outputKey
    }

    private fun getHMACSHA256(key : ByteArray, data : ByteArray) : ByteArray{
        val secretKey = SecretKeySpec(key, "HmacSHA256")
        val md = Mac.getInstance("HmacSHA256")
        md.init(secretKey)
        return md.doFinal(data)
    }

    private fun getHashFromString(message : String) : BigInteger {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(message.toByteArray())
        return BigInteger(digest)
    }

    private fun getRandomBigIntegerFrom(value: BigInteger): BigInteger {
        val rand = SecureRandom()
        val bytes = value.toByteArray()
        rand.nextBytes(bytes)
        bytes[bytes.lastIndex] = 0
        return BigInteger(1, bytes)
    }
}