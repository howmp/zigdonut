const std = @import("std");
const rva2va = @import("peloader.zig").rva2va;
const win32 = @import("struct.zig");

extern const __argc: c_int;
extern const __argv: [*c][*c]u8;
pub fn main() u8 {
    var allocator = std.heap.c_allocator;
    var wipeHeader = false;
    var infile: []const u8 = "";
    var outfile: []const u8 = "";
    var ok = false;
    if (__argc == 4) {
        if (std.mem.eql(u8, std.mem.span(__argv[1]), "-w")) {
            wipeHeader = true;
            ok = true;
        }
        infile = std.mem.span(__argv[2]);
        outfile = std.mem.span(__argv[3]);
    } else if (__argc == 3) {
        infile = std.mem.span(__argv[1]);
        outfile = std.mem.span(__argv[2]);
        ok = true;
    }
    if (!ok or infile.len == 0 or outfile.len == 0) {
        std.debug.print("usage: \nzigdonut.exe -w infile outfile\t(wipe header)\nzigdonut.exe    infile outfile\t(without wipe header)\n", .{});
        return 1;
    }

    std.debug.print(
        "infile: {s} outfile: {s} wipeheader: {}\n",
        .{ infile, outfile, wipeHeader },
    );

    var data = readFile(infile, allocator) catch |err| {
        std.debug.print("read file: {s} error: {s}\n", .{ infile, @errorName(err) });
        return 2;
    };
    var is64 = is64PE(data) catch |err| {
        std.debug.print("file: {s} error: {s}\n", .{ infile, @errorName(err) });
        return 3;
    };
    std.debug.print("is64: {}\n", .{is64});
    defer allocator.free(data);
    writeShellCode(data, is64, outfile, wipeHeader, allocator) catch |err| {
        std.debug.print("write file: {s} error: {s}\n", .{ outfile, @errorName(err) });
        return 4;
    };
    return 0;
}

fn is64PE(data: []u8) !bool {
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(data.ptr));
    if (dos.e_magic != 0x5A4D) {
        return error.NotPE;
    }
    var nt = rva2va(*win32.IMAGE_NT_HEADERS, data.ptr, @as(u32, @bitCast(dos.e_lfanew)));
    if (nt.Signature != 0x00004550) {
        return error.NotPE;
    }
    return nt.FileHeader.Machine == 0x8664;
}

const peloader32 = @embedFile("bin/peloader32.sc");
const peloader64 = @embedFile("bin/peloader64.sc");

fn writeShellCode(data: []u8, is64: bool, outpath: []const u8, wipeHeader: bool, allocator: std.mem.Allocator) !void {
    // compress
    std.debug.print("compress...\n", .{});

    var zipdata = try ap_compress(data, allocator);
    defer allocator.free(zipdata);
    std.debug.print("compressed({}%) {} -> {}\n", .{ zipdata.len * 100 / data.len, data.len, zipdata.len });
    // encrypt
    var key: [128]u8 = undefined;
    std.os.getrandom(&key) catch unreachable;
    std.debug.print("key: {s}\n", .{std.fmt.fmtSliceHexLower(&key)});
    for (0..zipdata.len) |i| {
        zipdata[i] ^= key[i % key.len];
    }
    var f = try std.fs.cwd().createFile(outpath, .{});
    var writer = f.writer();

    // 4 for rlen,4 for packlen,128 for keyBytes,1 for wipe header,
    const infolen = 4 + 4 + 128 + 1;
    var instlen = infolen + zipdata.len;

    // pic
    // call $+instlen
    try writer.writeByte(0xE8);
    try writer.writeIntLittle(u32, @as(u32, @truncate(instlen)));

    // rlen
    try writer.writeIntLittle(u32, @as(u32, @truncate(data.len)));
    // packlen
    try writer.writeIntLittle(u32, @as(u32, @truncate(zipdata.len)));
    // key
    _ = try writer.writeAll(&key);
    // wipeHeader
    try writer.writeByte(if (wipeHeader) 1 else 0);
    // compress data
    _ = try writer.writeAll(zipdata);
    // pop ecx
    try writer.writeByte(0x59);
    if (!is64) {
        // pop edx  ;保存返回地址到edx
        // push ecx ;压入inst地址
        // push edx  ;压入返回地址作为参数
        _ = try writer.writeAll("\x5a\x51\x52");
        _ = try writer.writeAll(peloader32);
    } else {
        // 通过寄存器传递rcx参数
        _ = try writer.writeAll(peloader64);
    }
    std.debug.print("write file ok\n", .{});
    return;
}

pub fn readFile(filename: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var f = try std.fs.cwd().openFile(filename, .{});
    defer f.close();
    var size = try f.getEndPos();
    var data = try allocator.alloc(u8, @truncate(size));
    _ = try f.readAll(data);
    return data;
}

const c = @cImport({
    @cInclude("shrink.h");
    @cInclude("expand.h");
});
fn ap_compress(data: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var outlen: usize = c.apultra_get_max_compressed_size(data.len);
    var stream = try std.ArrayList(u8).initCapacity(allocator, outlen);
    var buf = stream.items;
    var rlen = c.apultra_compress(data.ptr, buf.ptr, data.len, outlen, 0, 0, 0, null, null);
    if (rlen == @as(usize, @bitCast(@as(isize, -1)))) {
        stream.deinit();
        return error.apultra;
    }
    try stream.resize(rlen);
    return try stream.toOwnedSlice();
}
