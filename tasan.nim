# --panics:on --gc:arc -d:useMalloc -t:"-O3 -fsanitize=address,undefined"
# -l:"-fsanitize=address,undefined" -d:nosignalhandler -d:danger -g

import os, strutils, algorithm

var
  data: array[1000, int]

proc main: int =
  fill data, -1
  let idx = parseInt(paramStr(1))
  result = data[idx + 100]

discard main()

#[
const
  arrLen = 1_000

type
  Array = object
    data: ptr array[arrLen, int]

proc `=destroy`*(x: var Array) =
  if x.data != nil:
    dealloc(x.data)

proc init(x: var Array) =
  x.data = cast[typeof(x.data)](alloc(arrLen * sizeof(int)))

proc main =
  var
    arr: Array
  init arr
  `=destroy`(arr)
  echo arr.data[0]

main()]#
