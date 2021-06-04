import nake, std/[os, strformat]

task "doc", "Generate documentation":
  let
    src = "fuzztarget.nim"
    dir = "docs/"
    url = "https://github.com/planetis-m/libfuzzer"
    doc = dir / src.changeFileExt(".html")
    idx = dir / "index.html"
  if idx.needsRefresh(src):
    direShell(nimExe, &" doc --git.url:{url} --git.devel:master --out:{dir} {src}")
    moveFile(doc, idx)
  else:
    echo "All done!"
