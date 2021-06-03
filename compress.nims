--cc: clang
when not defined(fuzzSa):
  --noMain: on
  --passC: "-fsanitize=fuzzer"
  --passL: "-fsanitize=fuzzer"
--passC: "-fsanitize=address,undefined"
--passL: "-fsanitize=address,undefined"
--define: noSignalHandler
--define: useMalloc
#--debugger:native # ignored
