# https://www.youtube.com/watch?v=hFva8kJQwnc
# a vulnerable C program to explain common vulnerability types fuzz with libfuzzer
# ./imgread -fork=1 -ignore_crashes=1

type
  Image = object
    header: array[4, char]
    width, height: cint
    data: array[10, char]

proc testOneInput(data: openarray[byte]): cint {.
    exportc: "LLVMFuzzerTestOneInput".} =
  if data.len <= 12:
    return 0
  let img = cast[ptr Image](data)
  # integer overflow 0x7FFFFFFF+1=0
  # 0x7FFFFFFF+2 = 1
  # will cause very large/small memory allocation.
  let size1 = img.width + img.height
  var buff1 = cast[cstring](alloc(size1))
  # heap buffer overflow
  copyMem(buff1, addr img.data, sizeof(img.data))
  dealloc(buff1)
  # double dealloc
  if size1 div 3 == 0:
    dealloc(buff1)
  else:
    # use after dealloc
    if size1 div 20 == 0:
      buff1[0] = 'a'
  # integer underflow 0-1=-1
  # negative so will cause very large memory allocation
  let size2 = img.width - img.height + 100
  # echo("Size1: ", size1)
  let buff2 = cast[cstring](alloc(size2))
  # heap buffer overflow
  copyMem(buff2, addr img.data, sizeof(img.data))
  # divide by zero
  let size3 = img.width div img.height
  # echo("Size2: ", size3)
  var buff3: array[10, char]
  var buff4 = cast[cstring](alloc(size3))
  copyMem(buff4, addr img.data, sizeof(img.data))
  # stack OOBR read bytes past buffer
  let OOBR_stack = buff3[size3]
  let OOBR_heap = buff4[size1]
  # stack OOBW write bytes past buffer
  buff3[size3] = 'c'
  buff4[size1] = 'c'
  if size3 div 5 == 0:
    # memory leak here
    buff4 = nil
  else:
    dealloc(buff4)
  dealloc(buff2)
