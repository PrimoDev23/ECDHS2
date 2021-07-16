import java.math.BigInteger

class Curve(){
    var p : BigInteger = BigInteger.ZERO
    var a : BigInteger = BigInteger.ZERO
    var b : BigInteger = BigInteger.ZERO
    var gx : BigInteger = BigInteger.ZERO
    var n : BigInteger = BigInteger.ZERO
    var h : BigInteger = BigInteger.ZERO

    constructor(p : String, a : String, b : String, gx : String, n : String, h : String) : this(){
        this.p = BigInteger("0$p", 16)
        this.a = BigInteger("0$a", 16)
        this.b = BigInteger("0$b", 16)
        this.gx = BigInteger("0$gx", 16)
        this.n = BigInteger("0$n", 16)
        this.h = BigInteger("0$h", 16)
    }
}
