(module
  (import "env" "memory" (memory 1 65536 shared))
  (import "env" "__indirect_function_table" (table 1 funcref))
  (import "env" "__stack_pointer" (global (mut i32)))
  (func (export "__wasm_call_ctors"))
)
