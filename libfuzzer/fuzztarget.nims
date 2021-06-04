--cc: clang
--debugger:native # ignored
--define: noSignalHandler
--define: useMalloc
when not defined(fuzzSa):
  --noMain: on
  --passC: "-fsanitize=fuzzer"
  --passL: "-fsanitize=fuzzer"
--passC: "-fsanitize=address,undefined"
--passL: "-fsanitize=address,undefined"
