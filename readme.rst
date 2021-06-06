=========================================================
                        libFuzzer
=========================================================

Thin interface for LLVM/Clang libFuzzer, an in-process, coverage-guided,
evolutionary fuzzing engine.

Introduction
============

Fuzzing is a type of automated testing which continuously manipulates inputs to
a program to find issues such as panics or bugs. These semi-random data mutations
can discover new code coverage that existing unit tests may miss, and uncover
edge case bugs which would otherwise go unnoticed. Since fuzzing can reach these
edge cases, fuzz testing is particularly valuable for finding security exploits
and vulnerabilities.

Read the `Documentation <https://planetis-m.github.io/libfuzzer/fuzztarget.html>`_

Clang Sanitizers
================

Sanitizers are compiler build-in error detectors with relatively small runtime
cost. Clang has:

- `AddressSanitizer <https://clang.llvm.org/docs/AddressSanitizer.html>`_ - use-after-free, double-free, ...
- `MemorySanitizer <https://clang.llvm.org/docs/MemorySanitizer.html>`_ - uninitialized reads
- `UndefinedBehaviourSanitizer <https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html>`_ - overflows, divide by zero, ...
- `ThreadSanitizer <https://clang.llvm.org/docs/ThreadSanitizer.html>`_ - data races

For more information watch the talk *Sanitize your C++ code* [4]_
There are demos at the `tests <tests/>`_ directory.

Example
=======

In 95% of cases all you need is to define the procedure ``testOneInput`` in your file.


.. code-block:: nim

  proc fuzzMe(data: openarray[byte]): bool =
    result = data.len >= 3 and
      data[0].char == 'F' and
      data[1].char == 'U' and
      data[2].char == 'Z' and
      data[3].char == 'Z' # :‑<

  proc testOneInput(data: ptr UncheckedArray[byte], len: int): cint {.
      exportc: "LLVMFuzzerTestOneInput".} =
    result = 0
    discard fuzzMe(data.toOpenArray(0, len-1))


Compile with:

.. code-block::

  $ nim c --cc:clang -t:"-fsanitize=fuzzer,address" -l:"-fsanitize=fuzzer,address" -d:nosignalhandler --nomain:on -g tfuzz.nim


Coverage report
===============

Use `Clang Coverage <http://clang.llvm.org/docs/SourceBasedCodeCoverage.html>`_ to visualize and study your code coverage.

- Include the `standalone <libfuzzer/standalone.nim>`_ main procedure for fuzz targets.
- Follow the instructions given at the `test coverage <tests/tcov.nim>`_ example.
- When running the executable, pass as parameter a list of test units.

Structure-Aware Fuzzing
=======================

  But the lack of an input grammar can also result in inefficient fuzzing
  for complicated input types, where any traditional mutation (e.g. bit
  flipping) leads to an invalid input rejected by the target API in the
  early stage of parsing. With some additional effort, however, libFuzzer
  can be turned into a grammar-aware (i.e. structure-aware) fuzzing engine
  for a specific input type.

—*Structure-Aware Fuzzing with libFuzzer* [5]_

Take a look at the snappy compression `example <examples/compress/>`_.

Installation
============

- Copy the files ``libfuzzer/fuzztarget.{nim,nims}``, ``libfuzzer/standalone.nim`` at your testing directory.
- Fill in the implementations of the exported procedures.
- Compile and run with an empty corpus directory as an argument.

Presentations
=============

.. [#] Jonathan Metzman `Fuzzing 101 <https://www.youtube.com/watch?v=NI2w6eT8p-E>`_
.. [#] Kostya Serebryany `Fuzz or lose... <https://www.youtube.com/watch?v=k-Cv8Q3zWNQ>`_
.. [#] Kostya Serebryany `Sanitize your C++ code <https://www.youtube.com/watch?v=V2_80g0eOMc>`_

Further Readings
================

.. [#] `libFuzzer Tutorial <https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md>`_
.. [#] `Structure-Aware Fuzzing with libFuzzer <https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md>`_
.. [#] `Efficient Fuzzing Guide <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/testing/libfuzzer/efficient_fuzzing.md#efficient-fuzzing-guide>`_
