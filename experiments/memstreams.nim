import std/streams

type
  MemStream* = ref MemStreamObj
    ## A stream that encapsulates a openarray[byte].
  MemStreamObj = object of StreamObj
    data: ptr UncheckedArray[byte]
    len, pos: int

proc `=sink`*(dest: var MemStreamObj; source: MemStreamObj) {.error.}
proc `=copy`*(dest: var MemStreamObj; source: MemStreamObj) {.error.}

proc msAtEnd(s: Stream): bool =
  let s = MemStream(s)
  result = s.pos >= s.len

proc msSetPosition(s: Stream, pos: int) =
  let s = MemStream(s)
  s.pos = clamp(pos, 0, s.len)

proc msGetPosition(s: Stream): int =
  let s = MemStream(s)
  result = s.pos

proc msReadData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = MemStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
    inc(s.pos, result)
  else:
    result = 0

proc msPeekData(s: Stream, buffer: pointer, bufLen: int): int =
  let s = MemStream(s)
  result = min(bufLen, s.len - s.pos)
  if result > 0:
    copyMem(buffer, addr s.data[s.pos], result)
  else:
    result = 0

proc msWriteData(s: Stream, buffer: pointer, bufLen: int) =
  var s = MemStream(s)
  if bufLen <= 0:
    return
  if s.pos + bufLen > s.len:
    raise newException(IOError, "cannot write to stream")
  copyMem(addr(s.data[s.pos]), buffer, bufLen)
  inc(s.pos, bufLen)

proc newMemStream*(s: openarray[byte]): MemStream =
  result = MemStream(
    data: cast[ptr UncheckedArray[byte]](s),
    len: s.len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: msAtEnd,
    setPositionImpl: msSetPosition,
    getPositionImpl: msGetPosition,
    readDataStrImpl: nil,
    readDataImpl: msReadData,
    peekDataImpl: msPeekData,
    writeDataImpl: msWriteData
  )

proc newMemStream*(data: ptr UncheckedArray[byte], len: int): MemStream =
  result = MemStream(
    data: data,
    len: len,
    pos: 0,
    closeImpl: nil,
    atEndImpl: msAtEnd,
    setPositionImpl: msSetPosition,
    getPositionImpl: msGetPosition,
    readDataStrImpl: nil,
    readDataImpl: msReadData,
    peekDataImpl: msPeekData,
    writeDataImpl: msWriteData
  )
