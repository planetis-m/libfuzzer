--cc: clang
when not defined(standalone):
  --noMain: on
--define: noSignalHandler
--define: useMalloc
--passC: "-fsanitize=address,undefined"
--passL: "-fsanitize=address,undefined"
