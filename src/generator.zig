const std = @import("std");
const rva2va = @import("peloader.zig").rva2va;
const st = @import("struct.zig");
const c = @cImport({
    @cInclude("shrink.h");
    @cInclude("expand.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
});

pub export fn main(argc: c_int, argv: [*][*:0]u8) c_int {
    var wipeHeader = false;
    var infile: [*:0]const u8 = "";
    var outfile: [*:0]const u8 = "";
    var ok = false;

    const args = argv[0..@intCast(argc)];

    if (argc == 4) {
        if (std.mem.eql(u8, std.mem.sliceTo(args[1], 0), "-w")) {
            wipeHeader = true;
            ok = true;
        }
        infile = args[2];
        outfile = args[3];
    } else if (argc == 3) {
        infile = args[1];
        outfile = args[2];
        ok = true;
    }
    if (!ok) {
        std.debug.print("usage: \nzigdonut -w infile outfile\t(wipe header)\nzigdonut    infile outfile\t(without wipe header)\n", .{});
        return 1;
    }

    std.debug.print(
        "infile: {s} outfile: {s} wipeheader: {}\n",
        .{ infile, outfile, wipeHeader },
    );

    var data = readFile(infile) orelse {
        std.debug.print("read file: {s} error\n", .{infile});
        return 2;
    };
    defer c.free(data.ptr);

    // 尝试PE格式
    if (is64PE(data)) |is64| {
        std.debug.print("is64 {}\n", .{is64});
        writeShellCode(data, is64, outfile, wipeHeader) catch {
            std.debug.print("write file: {s} error\n", .{outfile});
            return 4;
        };
        std.debug.print("write file ok\n", .{});
        return 0;
    } else |_| {
        std.debug.print("not PE, trying ELF...\n", .{});
    }

    // 尝试ELF格式
    if (is64DynElf(data)) |_| {
        std.debug.print("is 64 Dyn ELF\n", .{});
        elfWriteShellCode(data, outfile) catch {
            std.debug.print("write file: {s} error\n", .{outfile});
            return 4;
        };
        std.debug.print("write file ok\n", .{});
        return 0;
    } else |err| {
        std.debug.print("{s}\n", .{@errorName(err)});
    }

    std.debug.print("unsupported file format: {s}\n", .{infile});
    return 3;
}
fn is64DynElf(data: []u8) !void {
    if (data.len < @sizeOf(st.Elf64_Ehdr)) {
        return error.NotELF;
    }
    var eh: *st.Elf64_Ehdr = @ptrCast(@alignCast(data.ptr));
    if (!std.mem.eql(u8, eh.e_ident[0..st.SELFMAG], st.ELFMAG)) {
        return error.NotELF;
    }
    if (eh.e_ident[st.EI_CLASS] != st.ELFCLASS64) {
        return error.NotELFCLASS64;
    }
    if (eh.e_ident[st.EI_DATA] != st.ELFDATA2LSB) {
        return error.ELFDATA2LSB;
    }
    if (eh.e_type != st.ET_DYN) {
        return error.NotDYN;
    }
    if (eh.e_machine != st.EM_X86_64) {
        return error.NotX86_64;
    }
}
fn is64PE(data: []u8) !bool {
    var dos: *st.IMAGE_DOS_HEADER = @ptrCast(@alignCast(data.ptr));
    if (dos.e_magic != 0x5A4D) {
        return error.NotPE;
    }
    var nt = rva2va(*st.IMAGE_NT_HEADERS, data.ptr, @as(u32, @bitCast(dos.e_lfanew)));
    if (nt.Signature != 0x00004550) {
        return error.NotPE;
    }
    return nt.FileHeader.Machine == 0x8664;
}

const peloader32 = @embedFile("bin/peloader32.sc");
const peloader64 = @embedFile("bin/peloader64.sc");
const elfloader64 = @embedFile("bin/elfloader64.sc");

fn writeShellCode(data: []u8, is64: bool, outpath: [*:0]const u8, wipeHeader: bool) !void {
    // compress
    std.debug.print("compress...\n", .{});

    var zipdata = try ap_compress(data);
    defer c.free(zipdata.ptr);
    std.debug.print("compressed({}%) {} -> {}\n", .{ zipdata.len * 100 / data.len, data.len, zipdata.len });
    // encrypt
    var key: [128]u8 = undefined;
    std.os.getrandom(&key) catch unreachable;
    std.debug.print("key: {s}\n", .{std.fmt.fmtSliceHexLower(&key)});
    for (0..zipdata.len) |i| {
        zipdata[i] ^= key[i % key.len];
    }
    const f = c.fopen(outpath, "wb") orelse return error.FileOpenFailed;
    defer _ = c.fclose(f);

    // 4 for rlen,4 for packlen,128 for keyBytes,1 for wipe header,
    const infolen = 4 + 4 + 128 + 1;
    var instlen = infolen + zipdata.len;

    // pic
    // call $+instlen
    var buf: [4]u8 = undefined;
    _ = c.fwrite(&[_]u8{0xE8}, 1, 1, f);
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(instlen)));
    _ = c.fwrite(&buf, 4, 1, f);

    // rlen
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(data.len)));
    _ = c.fwrite(&buf, 4, 1, f);
    // packlen
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(zipdata.len)));
    _ = c.fwrite(&buf, 4, 1, f);
    // key
    _ = c.fwrite(&key, 128, 1, f);
    // wipeHeader
    _ = c.fwrite(&[_]u8{if (wipeHeader) @as(u8, 1) else 0}, 1, 1, f);
    // compress data
    _ = c.fwrite(zipdata.ptr, 1, zipdata.len, f);
    // pop ecx
    _ = c.fwrite(&[_]u8{0x59}, 1, 1, f);
    if (!is64) {
        // pop edx  ;保存返回地址到edx
        // push ecx ;压入inst地址
        // push edx  ;压入返回地址作为参数
        _ = c.fwrite("\x5a\x51\x52", 1, 3, f);
        _ = c.fwrite(peloader32.ptr, 1, peloader32.len, f);
    } else {
        // 通过寄存器传递rcx参数
        _ = c.fwrite(peloader64.ptr, 1, peloader64.len, f);
    }
}

fn elfWriteShellCode(data: []u8, outpath: [*:0]const u8) !void {
    // compress
    std.debug.print("compress (elf)...\n", .{});

    var zipdata = try ap_compress(data);
    defer c.free(zipdata.ptr);
    std.debug.print("compressed({}%) {} -> {}\n", .{ zipdata.len * 100 / data.len, data.len, zipdata.len });
    // encrypt
    var key: [128]u8 = undefined;
    std.os.getrandom(&key) catch unreachable;
    std.debug.print("key: {s}\n", .{std.fmt.fmtSliceHexLower(&key)});
    for (0..zipdata.len) |i| {
        zipdata[i] ^= key[i % key.len];
    }
    const f = c.fopen(outpath, "wb") orelse return error.FileOpenFailed;
    defer _ = c.fclose(f);

    // data结构: rlen(4) + packlen(4) + key(128) + compressed_data
    const infolen = 4 + 4 + 128;
    const instlen = infolen + zipdata.len;

    // ============================================================
    // ELF shellcode: 仅通过data参数自定位，其他参数运行时获取
    // go(output, argc, argv, envp, data)
    // System V ABI: rdi=output, rsi=argc, rdx=argv, rcx=envp, r8=data
    // ============================================================

    // call $+instlen  -- 将返回地址压栈(指向data起始)
    _ = c.fwrite(&[_]u8{0xE8}, 1, 1, f);
    var buf: [4]u8 = undefined;
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(instlen)));
    _ = c.fwrite(&buf, 4, 1, f);

    // rlen
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(data.len)));
    _ = c.fwrite(&buf, 4, 1, f);
    // packlen
    std.mem.writeIntLittle(u32, &buf, @as(u32, @truncate(zipdata.len)));
    _ = c.fwrite(&buf, 4, 1, f);
    // key
    _ = c.fwrite(&key, 128, 1, f);
    // compress data
    _ = c.fwrite(zipdata.ptr, 1, zipdata.len, f);

    // pop r8          ; r8 = data地址 (自定位)
    _ = c.fwrite(&[_]u8{ 0x41, 0x58 }, 2, 1, f);

    // jmp to elfloader64 shellcode
    _ = c.fwrite(elfloader64.ptr, 1, elfloader64.len, f);
}

pub fn readFile(filename: [*:0]const u8) ?[]u8 {
    var f = c.fopen(filename, "rb");
    if (f == null) return null;
    defer _ = c.fclose(f);

    _ = c.fseek(f, 0, c.SEEK_END);
    const size: usize = @intCast(c.ftell(f));
    _ = c.fseek(f, 0, c.SEEK_SET);

    const buf = c.malloc(size) orelse return null;
    const nread = c.fread(buf, 1, size, f);
    if (nread != size) {
        c.free(buf);
        return null;
    }
    return @as([*]u8, @ptrCast(buf))[0..size];
}

fn ap_compress(data: []const u8) ![]u8 {
    var outlen: usize = c.apultra_get_max_compressed_size(data.len);
    const buf = c.malloc(outlen) orelse return error.OutOfMemory;
    const buf_ptr: [*c]u8 = @ptrCast(buf);
    var rlen = c.apultra_compress(data.ptr, buf_ptr, data.len, outlen, 0, 0, 0, null, null);
    if (rlen == @as(usize, @bitCast(@as(isize, -1)))) {
        c.free(buf);
        return error.Compress;
    }
    return @as([*]u8, @ptrCast(buf))[0..rlen];
}
