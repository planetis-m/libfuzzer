import nake, std/[os, strformat]

task "doc", "Generate documentation":
  let
    src = "fuzztarget.nim"
    dir = "docs/"
    doc = dir / src.changeFileExt(".html")
    url = "https://github.com/planetis-m/libfuzzer"
  if doc.needsRefresh(src):
    direShell(nimExe, &" doc --git.url:{url} --git.devel:master --git.commit:master --out:{dir} {src}")
  else:
    echo "All done!"
