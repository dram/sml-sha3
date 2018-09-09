structure Tests = struct

fun bytesToString (bytes : Word8Vector.vector) : string =
    "<"
    ^ String.concatWith " "
                        (List.map Word8.toString (Word8Vector.toList bytes))
    ^ ">"

fun printResult prefix x = print (prefix ^ ": " ^ x ^ "\n")

fun main _ =
    let
        val value1 = Word8Vector.fromList []

        val () = (printResult "value1"
                  o bytesToString) value1

        val () = (printResult "value1 SHA3-256"
                  o bytesToString
                  o Sha3.sha3_256) value1

        val value2 = Byte.stringToBytes "abc"

        val () = (printResult "value2"
                  o bytesToString) value2

        val () = (printResult "value2 SHA3-256"
                  o bytesToString
                  o Sha3.sha3_256) value2
    in
        0
    end

end
