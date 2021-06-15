# nim c --cc:clang --gc:arc -t:"-fsanitize=leak" -l:"-fsanitize=leak" -d:usemalloc -d:nosignalhandler -g
type
  Node = ref object
    data: string
    tail: Node

proc main =
  let
    a = Node(data: "na")
    b = Node(data: "abc", tail: a)

  a.tail = b

  # Uncomment to leak strings
  #prepareMutation(a.data)
  #prepareMutation(b.data)

main()
