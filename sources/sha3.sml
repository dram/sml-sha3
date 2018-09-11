structure Sha3 :> SHA3 = struct

local
    structure A8S = Word8ArraySlice
    structure A8 = Word8Array
    structure A = Array
    structure V8S = Word8VectorSlice
    structure V8 = Word8Vector
    structure W64 = Word64
    structure W8 = Word8

    fun step (n : int, s : int, f : int -> unit) : unit =
        let
            fun loop i =
                if i < n then
                    ( f i
                    ; loop (i + s))
                else
                    ()
        in
            loop 0
        end

    fun rol64 (a : W64.word, n : Word.word) : W64.word =
        W64.>> (a, 0w64 - n mod 0w64) + W64.<< (a, n mod 0w64)

    fun keccak_f1600_on_lanes (lanes : W64.word array array) : unit =
        let
            (* θ *)
            fun theta_step () =
                let
                    val C =
                        A.tabulate (
                            5,
                            fn x =>
                               A.foldl W64.xorb 0w0 (A.sub (lanes, x)))
                    val D =
                        A.tabulate (
                            5,
                            fn x =>
                               W64.xorb (
                                   A.sub (C, (x + 4) mod 5),
                                   rol64 (A.sub (C, (x + 1) mod 5), 0w1)))
                in
                    A.appi
                        (fn (x, lane) =>
                            let
                                val d = A.sub (D, x)
                            in
                                A.modify (fn w => W64.xorb (w, d)) lane
                            end)
                        lanes
                end

            (* ρ and π *)
            fun rho_and_pi_step () =
                let
                    fun loop (t, x, y, current) =
                        if t < 0w24 then
                            let
                                val lane = A.sub (lanes, x)
                                val new_current = A.sub (lane, y)
                            in
                                A.update (
                                    lane,
                                    y,
                                    rol64 (current,
                                           (t + 0w1) * (t + 0w2) div 0w2))
                              ; loop (
                                    t + 0w1, y, (2 * x + 3 * y) mod 5,
                                    new_current)
                            end
                        else
                            ()
                in
                    loop (0w0, 0, 2, A.sub (A.sub (lanes, 1), 0))
                end

            (* χ *)
            fun chi_step () =
                step (
                    5, 1,
                    fn y =>
                       let
                           val T = A.tabulate (
                                   5,
                                   fn x => A.sub (A.sub (lanes, x), y))
                       in
                           A.appi
                               (fn (x, lane) =>
                                   A.update (
                                       lane,
                                       y,
                                       W64.xorb (
                                           A.sub (T, x),
                                           W64.andb (
                                               W64.notb (A.sub (
                                                              T,
                                                              (x + 1) mod 5)),
                                               A.sub (T, (x + 2) mod 5)))))
                               lanes
                       end)

            (* ι *)
            fun iota_step (j, R) =
                if j < 0w7 then
                    let
                        val R' =
                            W8.xorb (
                                W8.<< (R, 0w1), W8.>> (R, 0w7) * 0wx71)
                        val lane = A.sub (lanes, 0)
                    in
                        if W8.andb (R', 0w2) <> 0w0 then
                            A.update
                                (lane,
                                 0,
                                 W64.xorb (
                                     A.sub (lane, 0),
                                     W64.<< (0w1, Word.<< (0w1, j) - 0w1)))
                        else
                            ()
                      ; iota_step (j + 0w1, R')
                    end
                else
                    R

            fun loop (round, R) =
                if round < 24 then
                    ( theta_step ()
                    ; rho_and_pi_step ()
                    ; chi_step ()
                    ; loop (round + 1, iota_step (0w0, R)))
                else
                    ()
        in
            loop (0, 0w1)
        end

    fun load64 (buffer : A8.array, index : int) : W64.word =
        A8S.foldr
            (fn (x, acc) =>
                (* TODO: Replace with `Word64.toLarge`, which is
                   unimplemented in SML/NJ yet *)
                W64.<< (acc, 0w8) + W64.fromInt (W8.toInt x))
            0w0
            (A8S.slice (buffer, index, SOME 8))

    fun store64 (buffer : A8.array, index : int, value : W64.word) : unit =
        let
            fun loop (i : int, w : W64.word) =
                if i < 8 then
                    let
                        (* TODO: Replace with `Word64.toLarge`, which is
                           unimplemented in SML/NJ yet *)
                        val byte = W8.fromLargeInt (W64.toLargeIntX w)
                        val rest = W64.>> (w, 0w8)
                    in
                        A8.update (buffer, index + i, byte)
                      ; loop (i + 1, rest)
                    end
                else
                    ()
        in
            loop (0, value)
        end

    fun keccak_f1600 (state : A8.array) : unit =
        let
            val lanes = A.tabulate (
                    5, fn x =>
                          A.tabulate (
                              5, fn y => load64 (state, 8 * (x + 5 * y))))
        in
            keccak_f1600_on_lanes lanes
          ; A.appi
                (fn (x, lane) =>
                    A.appi
                        (fn (y, value) =>
                            store64 (state, 8 * (x + 5 * y), value))
                        lane)
                lanes
        end
in
fun keccak (rate : int,
            capacity : int,
            inputBytes : V8.vector,
            delimitedSuffix : W8.word,
            outputByteLen : int) : V8.vector =
    (* TODO: assert (rate + capacity = 1600 and rate mod 8 == 0) *)
    let
        val inputSize = V8.length inputBytes
        val state = A8.array (200, 0w0)
        val rateInBytes = rate div 8

        (* absorb *)
        val () =
            step (
                inputSize, rateInBytes,
                fn inputOffset =>
                   let
                       val blockSize =
                           Int.min (inputSize - inputOffset, rateInBytes)
                   in
                       V8S.appi
                           (fn (i, byte) =>
                               A8.update (
                                   state,
                                   i,
                                   W8.xorb (A8.sub (state, i), byte)))
                           (V8S.slice (
                                 inputBytes, inputOffset, SOME blockSize))
                     ; if blockSize = rateInBytes then
                           keccak_f1600 state
                       else
                           ()
                   end)

        (* padding *)
        val blockSize = inputSize mod rateInBytes
        val () = A8.update (state,
                           blockSize,
                           W8.xorb
                               (A8.sub (state, blockSize), delimitedSuffix))
        val () = if W8.xorb (delimitedSuffix, 0wx80) <> 0w0
                    andalso blockSize = rateInBytes - 1 then
                     keccak_f1600 state
                 else
                     ()
        val () = A8.update (state,
                           rateInBytes - 1,
                           W8.xorb (A8.sub (state, rateInBytes - 1), 0wx80))
        val () = keccak_f1600 state

        (* squeeze *)
        fun loop (len) =
            if len > 0 then
                let
                    val blockSize = Int.min (len, rateInBytes)
                    val segment = A8S.vector (
                            A8S.slice (state, 0, SOME blockSize))
                    val remainSize = len - blockSize
                in
                    if remainSize > 0 then keccak_f1600 state else ()
                  ; V8.concat [segment, loop remainSize]
                end
            else
                V8.fromList []
    in
        loop outputByteLen
    end
end

fun keccak_224 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (1152, 448, inputBytes, 0wx01, 224 div 8)
fun keccak_256 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (1088, 512, inputBytes, 0wx01, 256 div 8)
fun keccak_384 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (832, 768, inputBytes, 0wx01, 384 div 8)
fun keccak_512 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (576, 1024, inputBytes, 0wx01, 512 div 8)

fun shake_128 (inputBytes : Word8Vector.vector,
               outputByteLen : int) : Word8Vector.vector =
    keccak (1344, 256, inputBytes, 0wx1f, outputByteLen)
fun shake_256 (inputBytes : Word8Vector.vector,
               outputByteLen : int) : Word8Vector.vector =
    keccak (1088, 512, inputBytes, 0wx1f, outputByteLen)

fun sha3_224 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (1152, 448, inputBytes, 0wx06, 224 div 8)
fun sha3_256 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (1088, 512, inputBytes, 0wx06, 256 div 8)
fun sha3_384 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (832, 768, inputBytes, 0wx06, 384 div 8)
fun sha3_512 (inputBytes : Word8Vector.vector) : Word8Vector.vector =
    keccak (576, 1024, inputBytes, 0wx06, 512 div 8)

end
