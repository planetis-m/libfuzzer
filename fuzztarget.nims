--cc: clang
when not defined(standalone):
  --nomain: on
--define: nosignalhandler
--passC: "-fsanitize=address,undefined"
--passL: "-fsanitize=address,undefined"
