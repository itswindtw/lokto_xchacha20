(lang dune 3.22)

(name lokto_xchacha20)

(generate_opam_files true)

(package
 (name lokto_xchacha20)
 (depends
  ocaml
  mirage-crypto
  (alcotest :with-test)
  (hex :with-test)
  (ocaml-lsp-server :with-dev-setup)
  (ocamlformat :with-dev-setup)))
