import streams

type
  ReadStream* = ref ReadStreamObj
    ## A stream that encapsulates a openarray[byte].
  ReadStreamObj = object of StreamObj
    data: ptr UncheckedArray[byte]
    len, pos: int

proc `=sink`*(dest: var ReadStreamObj; source: ReadStreamObj) {.error.}
proc `=copy`*(dest: var ReadStreamObj; source: ReadStreamObj) {.error.}

proc rsAtEnd(s: Stream): bool =
  let s = ReadStream(s)
  result = s.pos >= s.len

proc rsSetPosition(s: Stream, pos: int) =
  let s = ReadStream(s)
  s.pos = clamp(pos, 0, s.len)

proc rsGetPosition(s: Stream): int =
  let s = ReadStream(s)
  result = s.pos

proc rsReadData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = ReadStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
    inc(s.pos, result)
  else:
    result = 0

proc rsPeekData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = ReadStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
  else:
    result = 0

proc newReadStream*(s: openarray[byte]): ReadStream =
  result = ReadStream(
    data: cast[ptr UncheckedArray[byte]](s),
    len: s.len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: rsAtEnd,
    setPositionImpl: rsSetPosition,
    getPositionImpl: rsGetPosition,
    readDataStrImpl: nil,
    readDataImpl: rsReadData,
    peekDataImpl: rsPeekData,
    writeDataImpl: nil
  )
