# Package
version     = "0.1.0"
author      = "Antonis Geralis"
description = "Thin interface for libFuzzer, an in-process, coverage-guided, evolutionary fuzzing engine."
license     = "MIT"

# Deps
requires "nim >= 1.0.0"

import os

const
  ProjectUrl = "https://github.com/planetis-m/libfuzzer"
  PkgDir = thisDir().quoteShell
  DocsDir = PkgDir / "docs"

task docs, "Generate documentation":
  # https://nim-lang.github.io/Nim/docgen.html
  withDir(PkgDir):
    let tmp = "fuzztarget"
    let doc = DocsDir / (tmp & ".html")
    let src = "libfuzzer" / (tmp & ".nim")
    # Generate the docs for {src}
    exec("nim doc --verbosity:0 --git.url:" & ProjectUrl &
        " --git.devel:main --git.commit:main --out:" & doc & " " & src)
