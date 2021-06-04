# https://github.com/google/sanitizers/wiki/ThreadSanitizerPopularDataRaces
# pbl benign
# --threads:on --panics:on --gc:arc -d:useMalloc -t:"-fsanitize=thread"
# -l:"-fsanitize=thread" -d:nosignalhandler -d:danger -g
# TSAN_OPTIONS="force_seq_cst_atomics=1"
import std/[atomics, os]

const
  delay = 1_000

var
  thread: Thread[void]
  proceed: Atomic[bool]
  bArrived = false

proc routine =
  var count = 0
  while true:
    if count mod delay == 0 and proceed.load(moRelaxed):
      break
    cpuRelax()
    inc count
  doAssert bArrived

proc testNotify =
  createThread(thread, routine)
  sleep 10
  bArrived = true
  proceed.store(true, moRelaxed)
  joinThread thread

testNotify()
