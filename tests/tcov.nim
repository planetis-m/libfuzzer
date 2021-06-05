# --panics:on --gc:arc -d:useMalloc --cc:clang -t:"-fprofile-instr-generate -fcoverage-mapping"
# -l:"-fprofile-instr-generate -fcoverage-mapping" -d:danger
# Run the executable
# llvm-profdata merge -sparse=true default.profraw -o default.profdata
# llvm-cov show -instr-profile=default.profdata -name=foo_tcov ./tcov
# Missing:
# Output Nim source code
# Specify a Nim demangler with -Xdemangler
template bar(x: untyped): untyped = x or x

proc foo[T](x: T) =
  for i in 0..<10:
    discard bar i

proc main =
  foo[int32](0)
  foo[float32](0)

main()
