(* https://datatracker.ietf.org/doc/html/rfc8439 *)
(* https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03 *)

let quarter_round a b c d =
  let open Int32 in
  let left_roll x n = logor (shift_left x n) (shift_right_logical x (32 - n)) in
  (* 1 *)
  let a = add a b in
  let d = logxor d a in
  let d = left_roll d 16 in
  (* 2 *)
  let c = add c d in
  let b = logxor b c in
  let b = left_roll b 12 in
  (* 3 *)
  let a = add a b in
  let d = logxor d a in
  let d = left_roll d 8 in
  (* 4 *)
  let c = add c d in
  let b = logxor b c in
  let b = left_roll b 7 in
  (a, b, c, d)

let hchacha20 key nonce =
  (* constant: 16 bytes (0-3) *)
  let constant = "expand 32-byte k" in
  let s0 = String.get_int32_le constant 0 in
  let s1 = String.get_int32_le constant 4 in
  let s2 = String.get_int32_le constant 8 in
  let s3 = String.get_int32_le constant 12 in

  (* key: 32 bytes (4-11) *)
  let s4 = String.get_int32_le key 0 in
  let s5 = String.get_int32_le key 4 in
  let s6 = String.get_int32_le key 8 in
  let s7 = String.get_int32_le key 12 in
  let s8 = String.get_int32_le key 16 in
  let s9 = String.get_int32_le key 20 in
  let s10 = String.get_int32_le key 24 in
  let s11 = String.get_int32_le key 28 in

  (* nonce: 16 bytes (12-15) *)
  let s12 = String.get_int32_le nonce 0 in
  let s13 = String.get_int32_le nonce 4 in
  let s14 = String.get_int32_le nonce 8 in
  let s15 = String.get_int32_le nonce 12 in

  let rec loop i s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 =
    if i = 0 then
      (s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15)
    else
      let s0, s4, s8, s12 = quarter_round s0 s4 s8 s12 in
      let s1, s5, s9, s13 = quarter_round s1 s5 s9 s13 in
      let s2, s6, s10, s14 = quarter_round s2 s6 s10 s14 in
      let s3, s7, s11, s15 = quarter_round s3 s7 s11 s15 in

      let s0, s5, s10, s15 = quarter_round s0 s5 s10 s15 in
      let s1, s6, s11, s12 = quarter_round s1 s6 s11 s12 in
      let s2, s7, s8, s13 = quarter_round s2 s7 s8 s13 in
      let s3, s4, s9, s14 = quarter_round s3 s4 s9 s14 in
      loop (i - 1) s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15
  in

  let s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15 =
    loop 10 s0 s1 s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 s12 s13 s14 s15
  in

  let bytes = Bytes.create 32 in
  Bytes.set_int32_le bytes 0 s0;
  Bytes.set_int32_le bytes 4 s1;
  Bytes.set_int32_le bytes 8 s2;
  Bytes.set_int32_le bytes 12 s3;
  Bytes.set_int32_le bytes 16 s12;
  Bytes.set_int32_le bytes 20 s13;
  Bytes.set_int32_le bytes 24 s14;
  Bytes.set_int32_le bytes 28 s15;

  Bytes.unsafe_to_string bytes

let xchacha20_key_nonce key nonce =
  if String.length key <> 32 || String.length nonce <> 24 then
    invalid_arg "xchacha20: key must be 32 bytes, nonce 24 bytes";

  let first_16_bytes_of_nonce = String.sub nonce 0 16 in
  let last_8_bytes_of_nonce = String.sub nonce 16 8 in
  let subkey = hchacha20 key first_16_bytes_of_nonce in
  (subkey, last_8_bytes_of_nonce)

let authenticate_encrypt ~key ~nonce ?(aad = "") plaintext =
  let key, nonce = xchacha20_key_nonce key nonce in
  let key = Mirage_crypto.Chacha20.of_secret key in
  Mirage_crypto.Chacha20.authenticate_encrypt ~key ~nonce ~adata:aad plaintext

let authenticate_decrypt ~key ~nonce ?(aad = "") ciphertext =
  let key, nonce = xchacha20_key_nonce key nonce in
  let key = Mirage_crypto.Chacha20.of_secret key in
  Mirage_crypto.Chacha20.authenticate_decrypt ~key ~nonce ~adata:aad ciphertext
