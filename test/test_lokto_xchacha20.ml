open Alcotest

let tests =
  [
    test_case "quarter_round" `Quick (fun () ->
        let a = 0x11111111l in
        let b = 0x01020304l in
        let c = 0x9b8d6f43l in
        let d = 0x01234567l in
        let a, b, c, d = Lokto_xchacha20.quarter_round a b c d in

        check int32 "a" 0xea2a92f4l a;
        check int32 "b" 0xcb1cf8cel b;
        check int32 "c" 0x4581472el c;
        check int32 "d" 0x5881c4bbl d);
    test_case "hchacha20" `Quick (fun () ->
        let key =
          `Hex
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
          |> Hex.to_string
        in
        let nonce = `Hex "000000090000004a0000000031415927" |> Hex.to_string in
        let expected =
          `Hex
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
          |> Hex.to_string
        in
        let actual = Lokto_xchacha20.hchacha20 key nonce in

        check string "" expected actual);
    test_case "authenticate_encrypt" `Quick (fun () ->
        let plaintext =
          `Hex
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
          |> Hex.to_string
        in
        let aad = `Hex "50515253c0c1c2c3c4c5c6c7" |> Hex.to_string in
        let key =
          `Hex
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
          |> Hex.to_string
        in
        let nonce =
          `Hex "404142434445464748494a4b4c4d4e4f5051525354555657"
          |> Hex.to_string
        in
        let ciphertext =
          `Hex
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
          |> Hex.to_string
        in
        let tag = `Hex "c0875924c1c7987947deafd8780acf49" |> Hex.to_string in

        let expected = ciphertext ^ tag in
        let actual =
          Lokto_xchacha20.authenticate_encrypt ~key ~nonce ~aad plaintext
        in

        check string "" expected actual);
    test_case "authenticate_decrypt" `Quick (fun () ->
        let ciphertext =
          `Hex
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e"
          |> Hex.to_string
        in
        let plaintext =
          `Hex
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"
          |> Hex.to_string
        in
        let aad = `Hex "50515253c0c1c2c3c4c5c6c7" |> Hex.to_string in
        let key =
          `Hex
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
          |> Hex.to_string
        in
        let nonce =
          `Hex "404142434445464748494a4b4c4d4e4f5051525354555657"
          |> Hex.to_string
        in

        let tag = `Hex "c0875924c1c7987947deafd8780acf49" |> Hex.to_string in

        let expected = Some plaintext in
        let actual =
          Lokto_xchacha20.authenticate_decrypt ~key ~nonce ~aad
            (ciphertext ^ tag)
        in

        check (option string) "" expected actual);
  ]

let () = Alcotest.run "lokto_xchacha20" [ ("Test vectors", tests) ]
