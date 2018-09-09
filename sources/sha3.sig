signature SHA3 = sig
    val keccak
        : (int * int * Word8Vector.vector * Word8.word * int)
          -> Word8Vector.vector

    val keccak_224 : Word8Vector.vector -> Word8Vector.vector
    val keccak_256 : Word8Vector.vector -> Word8Vector.vector
    val keccak_384 : Word8Vector.vector -> Word8Vector.vector
    val keccak_512 : Word8Vector.vector -> Word8Vector.vector

    val shake_128 : (Word8Vector.vector * int) -> Word8Vector.vector
    val shake_256 : (Word8Vector.vector * int) -> Word8Vector.vector

    val sha3_224 : Word8Vector.vector -> Word8Vector.vector
    val sha3_256 : Word8Vector.vector -> Word8Vector.vector
    val sha3_384 : Word8Vector.vector -> Word8Vector.vector
    val sha3_512 : Word8Vector.vector -> Word8Vector.vector
end
