const std = @import("std");
const string = []const u8;

pub fn build(b: *std.Build) void {

    // peloaders for debug

    {
        inline for (&.{ .{ "x86", "32" }, .{ "x86_64", "64" } }) |t| {
            var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = t[0] ++ "-windows-msvc" }) catch unreachable;
            // var cpu_model = target.getCpuArch().parseCpuModel("generic") catch unreachable;
            // target.cpu_model = .{ .explicit = cpu_model };
            const exe = b.addExecutable(.{
                .name = "pedebug" ++ t[1],
                .root_source_file = .{ .path = "src/peloader.zig" },
                .target = target,
                .optimize = .ReleaseSmall,
            });
            exe.unwind_tables = false;
            exe.single_threaded = true;
            b.installArtifact(exe);
        }
    }

    // elfloader for debug (x86_64-linux only)

    {
        var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86_64-linux-musl" }) catch unreachable;
        const exe = b.addExecutable(.{
            .name = "elfdebug",
            .root_source_file = .{ .path = "src/elfloader.zig" },
            .target = target,
            .optimize = .ReleaseSmall,
        });
        exe.unwind_tables = false;
        exe.single_threaded = true;
        b.installArtifact(exe);
    }

    // peloaders for gen shellcode
    const peloaders_step = b.step("peloaders", "Build and ReleaseSmall peloaders dll and shellcode");

    {
        inline for (&.{ "x86", "x86_64" }) |arch| {
            var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = arch ++ "-windows-msvc" }) catch unreachable;
            // var cpu_model = target.getCpuArch().parseCpuModel("generic") catch unreachable;
            // target.cpu_model = .{ .explicit = cpu_model };
            const dll = b.addSharedLibrary(.{
                .name = "peloader-" ++ arch,
                .root_source_file = .{ .path = "src/peloader.zig" },
                .target = target,
                .optimize = .ReleaseSmall,
            });
            dll.single_threaded = true;
            const install = b.addInstallArtifact(dll, .{});
            const c = GenShellCode.create(b, install);
            peloaders_step.dependOn(&c.step);
        }
    }

    // elfloaders for gen shellcode (x86_64-linux only)
    const elfloaders_step = b.step("elfloaders", "Build and ReleaseSmall elfloaders so and shellcode");

    {
        var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86_64-linux-musl" }) catch unreachable;
        const so = b.addSharedLibrary(.{
            .name = "elfloader-x86_64",
            .root_source_file = .{ .path = "src/elfloader.zig" },
            .target = target,
            .optimize = .ReleaseSmall,
        });
        so.single_threaded = true;
        const install = b.addInstallArtifact(so, .{});
        const c = GenElfShellCode.create(b, install);
        elfloaders_step.dependOn(&c.step);
    }
    // elfscloader for debug (x86_64-linux only)
    {
        var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86_64-linux-musl" }) catch unreachable;
        const exe = b.addExecutable(.{
            .name = "elfscloader",
            .target = target,
            .optimize = .ReleaseSmall,
        });
        exe.addCSourceFile(.{ .file = .{ .path = "src/elfscloader.c" }, .flags = &.{} });
        exe.linkLibC();
        b.installArtifact(exe);
    }
    // test_elf for debug (x86_64-linux only)
    {
        var target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86_64-linux-musl" }) catch unreachable;
        const exe = b.addExecutable(.{
            .name = "test_elf",
            .target = target,
            .optimize = .ReleaseSmall,
        });
        exe.pie = true;
        exe.addCSourceFile(.{ .file = .{ .path = "src/test_elf.c" }, .flags = &.{
            "-Wall",
            "-Wextra",
            "-O2",
            "-std=c99",
        } });
        exe.linkLibC();
        b.installArtifact(exe);
    }
    // zigdonut for x86-windows-gnu
    {
        const gen = b.addExecutable(.{
            .name = "zigdonut",
            .root_source_file = .{ .path = "src/generator.zig" },
            .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86-windows-gnu" }) catch unreachable,
            .optimize = .ReleaseSmall,
        });
        gen.unwind_tables = false;
        var d = AddDeps.create(b, gen, genCpackages);
        gen.step.dependOn(&d.step);
        gen.step.dependOn(peloaders_step);
        b.installArtifact(gen);
    }

    // zigdonut for x86_64-linux-musl
    {
        const gen = b.addExecutable(.{
            .name = "zigdonut",
            .root_source_file = .{ .path = "src/generator.zig" },
            .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86_64-linux-musl" }) catch unreachable,
            .optimize = .ReleaseSmall,
        });
        gen.unwind_tables = false;
        var d = AddDeps.create(b, gen, genCpackages);
        gen.step.dependOn(&d.step);
        gen.step.dependOn(peloaders_step);
        gen.step.dependOn(elfloaders_step);
        b.installArtifact(gen);
    }
}

const st = @import("src/struct.zig");

fn getNt(base: *anyopaque) *anyopaque {
    var dos: *st.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    return @ptrFromInt(@intFromPtr(base) + @as(u32, @bitCast(dos.e_lfanew)));
}

fn rva2ofs(comptime T: type, base: *anyopaque, rva: usize, is64: bool) T {
    var nt = getNt(base);

    var sh: [*c]st.IMAGE_SECTION_HEADER = undefined;
    var shNum: usize = 0;
    if (is64) {
        var nt64: *st.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
        sh = @ptrFromInt(@intFromPtr(&nt64.OptionalHeader) + nt64.FileHeader.SizeOfOptionalHeader);
        shNum = nt64.FileHeader.NumberOfSections;
    } else {
        var nt32: *st.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
        sh = @ptrFromInt(@intFromPtr(&nt32.OptionalHeader) + nt32.FileHeader.SizeOfOptionalHeader);
        shNum = nt32.FileHeader.NumberOfSections;
    }

    var ofs: usize = 0;
    for (0..shNum) |i| {
        if (rva >= sh[i].VirtualAddress and rva < (sh[i].VirtualAddress + sh[i].SizeOfRawData)) {
            ofs = sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
            break;
        }
    }
    std.debug.assert(ofs != 0);
    var ptr = @intFromPtr(base) + ofs;
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

fn genShellCode(step: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
    _ = prog_node;
    const c = @fieldParentPtr(GenShellCode, "step", step);
    const allocator = step.owner.allocator;
    const is64 = c.install.artifact.target.cpu_arch == .x86_64;
    const shellcodePath = std.mem.concat(
        allocator,
        u8,
        &.{ "src/bin/", if (is64) "peloader64.sc" else "peloader32.sc" },
    ) catch unreachable;
    defer allocator.free(shellcodePath);

    {
        var dir = std.fs.cwd().openDir(step.owner.lib_dir, .{}) catch unreachable;
        defer dir.close();
        var inst = dir.readFileAllocOptions(
            allocator,
            c.install.dest_sub_path,
            1024 * 64,
            null,
            16,
            null,
        ) catch unreachable;
        // get shellcode by resolve go goEnd symbol
        var nt = getNt(inst.ptr);
        var rva: u32 = 0;
        if (is64) {
            var nt64: *st.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
            rva = nt64.OptionalHeader.DataDirectory[st.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            var nt32: *st.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
            rva = nt32.OptionalHeader.DataDirectory[st.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        std.debug.assert(rva != 0);
        var exp = rva2ofs(*st.IMAGE_EXPORT_DIRECTORY, inst.ptr, rva, is64);
        var cnt = exp.NumberOfNames;
        std.debug.assert(cnt != 0);
        var adr = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfFunctions, is64);
        var sym = rva2ofs([*c]align(1) u32, inst.ptr, exp.AddressOfNames, is64);
        var ord = rva2ofs([*c]align(1) u16, inst.ptr, exp.AddressOfNameOrdinals, is64);
        var goFn: [*c]u8 = undefined;
        var fnLen: usize = undefined;
        for (0..cnt) |i| {
            var sym_ = std.mem.sliceTo(rva2ofs([*c]u8, inst.ptr, sym[i], is64), 0);
            var adr_ = rva2ofs(usize, inst.ptr, adr[ord[i]], is64);
            if (std.mem.eql(u8, sym_, "go")) {
                goFn = @ptrFromInt(adr_);
            } else if (std.mem.eql(u8, sym_, "goEnd")) {
                fnLen = adr_ - @as(usize, @intFromPtr(goFn));
            }
        }
        var shellcode = goFn[0..fnLen];

        // write shellcode
        std.fs.cwd().writeFile(shellcodePath, shellcode) catch unreachable;
    }
}

/// gen shellcode
const GenShellCode = struct {
    step: std.Build.Step,
    install: *std.Build.Step.InstallArtifact,
    fn create(owner: *std.Build, install: *std.Build.Step.InstallArtifact) *GenShellCode {
        const self = owner.allocator.create(GenShellCode) catch unreachable;

        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .install_artifact,
                .name = owner.fmt("generate shellcode for {s}", .{install.artifact.name}),
                .owner = owner,
                .makeFn = genShellCode,
            }),
            .install = install,
        };
        self.step.dependOn(&install.step);
        return self;
    }
};

fn genElfShellCode(step: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
    _ = prog_node;
    const c = @fieldParentPtr(GenElfShellCode, "step", step);
    const allocator = step.owner.allocator;

    const shellcodePath = "src/bin/elfloader64.sc";

    {
        var dir = std.fs.cwd().openDir(step.owner.lib_dir, .{}) catch unreachable;
        defer dir.close();
        var inst = dir.readFileAllocOptions(
            allocator,
            c.install.dest_sub_path,
            1024 * 64,
            null,
            16,
            null,
        ) catch unreachable;

        // Parse ELF to find go and goEnd symbols via .dynsym
        var eh: *st.Elf64_Ehdr = @ptrCast(@alignCast(inst.ptr));
        var phdrs: [*c]st.Elf64_Phdr = @ptrCast(@alignCast(inst.ptr + @as(usize, @intCast(eh.e_phoff))));

        // Find PT_DYNAMIC
        var dyn_offset: u64 = 0;
        var dyn_size: u64 = 0;
        for (0..eh.e_phnum) |i| {
            if (phdrs[i].p_type == st.PT_DYNAMIC) {
                dyn_offset = phdrs[i].p_offset;
                dyn_size = phdrs[i].p_filesz;
                break;
            }
        }
        std.debug.assert(dyn_offset != 0);

        // Parse dynamic entries to find DT_SYMTAB, DT_STRTAB, DT_GNU_HASH
        var dyn: [*c]st.Elf64_Dyn = @ptrCast(@alignCast(inst.ptr + @as(usize, @intCast(dyn_offset))));
        var dyn_cnt: usize = @intCast(dyn_size / @sizeOf(st.Elf64_Dyn));

        var symtab_vaddr: u64 = 0;
        var strtab_vaddr: u64 = 0;
        var gnu_hash_vaddr: u64 = 0;
        var hash_vaddr: u64 = 0;

        for (0..dyn_cnt) |i| {
            if (dyn[i].d_tag == 6) { // DT_SYMTAB
                symtab_vaddr = dyn[i].d_un.d_ptr;
            } else if (dyn[i].d_tag == 5) { // DT_STRTAB
                strtab_vaddr = dyn[i].d_un.d_ptr;
            } else if (dyn[i].d_tag == 0x6ffffef5) { // DT_GNU_HASH
                gnu_hash_vaddr = dyn[i].d_un.d_ptr;
            } else if (dyn[i].d_tag == 4) { // DT_HASH
                hash_vaddr = dyn[i].d_un.d_ptr;
            }
        }
        std.debug.assert(symtab_vaddr != 0);
        std.debug.assert(strtab_vaddr != 0);

        const Dynsym64 = extern struct {
            st_name: u32,
            st_info: u8,
            st_other: u8,
            st_shndx: u16,
            st_value: u64,
            st_size: u64,
        };

        // Determine number of symbols
        var nsyms: u32 = 0;
        if (hash_vaddr != 0) {
            // DT_HASH: nchain field is at offset 4
            var hash_ptr: [*c]align(1) u32 = elfVaddr2FileOff([*c]align(1) u32, inst.ptr, hash_vaddr, phdrs, eh.e_phnum);
            nsyms = hash_ptr[1]; // nchain
        } else if (gnu_hash_vaddr != 0) {
            // DT_GNU_HASH for ELF64
            // Header: nbuckets(u32), symoffset(u32), bloom_size(u32), bloom_shift(u32)
            // Then: bloom[bloom_size] as u64, buckets[nbuckets] as u32, chains[] as u32
            var gnu_hash_ptr: [*c]align(1) u32 = elfVaddr2FileOff([*c]align(1) u32, inst.ptr, gnu_hash_vaddr, phdrs, eh.e_phnum);
            var nbuckets = gnu_hash_ptr[0];
            var symoffset = gnu_hash_ptr[1];
            var bloom_size = gnu_hash_ptr[2];
            // bloom filter entries are u64 for ELF64
            var bloom_end: usize = @intFromPtr(gnu_hash_ptr) + 16 + bloom_size * @sizeOf(u64);
            var buckets: [*c]align(1) u32 = @ptrFromInt(bloom_end);
            var chains: [*c]align(1) u32 = @ptrFromInt(bloom_end + nbuckets * @sizeOf(u32));

            // Find max bucket value
            var max_sym: u32 = 0;
            for (0..nbuckets) |i| {
                if (buckets[i] > max_sym) max_sym = buckets[i];
            }

            if (max_sym >= symoffset) {
                var chain_idx: usize = max_sym - symoffset;
                nsyms = max_sym + 1;
                while (chains[chain_idx] != 0) {
                    chain_idx += 1;
                    nsyms += 1;
                }
            } else {
                nsyms = symoffset;
            }
        }
        std.debug.assert(nsyms != 0);

        var symtab: [*c]align(1) Dynsym64 = elfVaddr2FileOff([*c]align(1) Dynsym64, inst.ptr, symtab_vaddr, phdrs, eh.e_phnum);
        var strtab: [*c]align(1) u8 = elfVaddr2FileOff([*c]align(1) u8, inst.ptr, strtab_vaddr, phdrs, eh.e_phnum);

        var goFn: [*c]u8 = undefined;
        var fnLen: usize = undefined;
        for (0..nsyms) |i| {
            var name: [*c]u8 = @ptrFromInt(@intFromPtr(strtab) + symtab[i].st_name);
            var nameSlice = std.mem.sliceTo(name, 0);
            if (std.mem.eql(u8, nameSlice, "go")) {
                goFn = elfVaddr2FileOff([*c]u8, inst.ptr, symtab[i].st_value, phdrs, eh.e_phnum);
            } else if (std.mem.eql(u8, nameSlice, "goEnd")) {
                fnLen = @intFromPtr(elfVaddr2FileOff([*c]u8, inst.ptr, symtab[i].st_value, phdrs, eh.e_phnum)) - @intFromPtr(goFn);
            }
        }
        var shellcode = goFn[0..fnLen];

        // write shellcode
        std.fs.cwd().writeFile(shellcodePath, shellcode) catch unreachable;
    }
}

fn elfVaddr2FileOff(comptime T: type, base: [*c]u8, vaddr: u64, phdrs: [*c]st.Elf64_Phdr, phnum: u16) T {
    for (0..phnum) |i| {
        if (phdrs[i].p_type == st.PT_LOAD) {
            if (vaddr >= phdrs[i].p_vaddr and vaddr < phdrs[i].p_vaddr + phdrs[i].p_memsz) {
                var offset = vaddr - phdrs[i].p_vaddr + phdrs[i].p_offset;
                var ptr = @intFromPtr(base) + @as(usize, @intCast(offset));
                return switch (@typeInfo(T)) {
                    .Pointer => @as(T, @ptrFromInt(ptr)),
                    .Int => @as(T, @intCast(ptr)),
                    else => @compileError("expected pointer or int"),
                };
            }
        }
    }
    std.debug.panic("elfVaddr2FileOff: vaddr 0x{X} not found in any LOAD segment", .{vaddr});
}

/// gen elf shellcode
const GenElfShellCode = struct {
    step: std.Build.Step,
    install: *std.Build.Step.InstallArtifact,
    fn create(owner: *std.Build, install: *std.Build.Step.InstallArtifact) *GenElfShellCode {
        const self = owner.allocator.create(GenElfShellCode) catch unreachable;

        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .install_artifact,
                .name = owner.fmt("generate elf shellcode for {s}", .{install.artifact.name}),
                .owner = owner,
                .makeFn = genElfShellCode,
            }),
            .install = install,
        };
        self.step.dependOn(&install.step);
        return self;
    }
};

const CPackage = struct {
    directory: string,
    c_source_dir: string,
    c_include_dirs: []const string,
    c_source_flags: []const string,
    windows_libs: []const string,
    os: ?std.Target.Os.Tag = null,
};

const genCpackages: []const CPackage = &.{
    CPackage{
        .directory = "deps/apultra1.4.8/",
        .c_include_dirs = &.{"inc"},
        .c_source_dir = "src",
        .c_source_flags = &.{
            "-std=gnu99",
        },
        .windows_libs = &.{},
    },
};

fn addDeps(step: *std.Build.Step, prog_node: *std.Progress.Node) anyerror!void {
    _ = prog_node;
    const self = @fieldParentPtr(AddDeps, "step", step);
    const cpackages = self.packages;
    const exe = self.exe;
    const b = step.owner;
    for (cpackages) |cpkg| {
        if (cpkg.os) |os| {
            if (os != exe.target.getOsTag()) {
                continue;
            }
        }
        if (exe.target.isWindows()) {
            // 链接windows库
            for (cpkg.windows_libs) |lib| {
                exe.linkSystemLibrary(lib);
            }
        }
        for (cpkg.c_include_dirs) |inc| {
            var path = b.pathJoin(&.{ cpkg.directory, inc });

            exe.addIncludePath(std.build.LazyPath.relative(path));
        }
        var srcpath = b.pathJoin(&.{ cpkg.directory, cpkg.c_source_dir });
        var dir = std.fs.cwd().openIterableDir(srcpath, .{}) catch unreachable;
        defer dir.close();
        var walker = dir.walk(b.allocator) catch unreachable;
        defer walker.deinit();
        var fileList = std.ArrayList([]const u8).init(b.allocator);

        while (walker.next() catch unreachable) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.path, ".c")) {
                fileList.append(b.pathJoin(&.{ srcpath, entry.path })) catch unreachable;
            }
        }
        var files = fileList.toOwnedSlice() catch unreachable;
        exe.addCSourceFiles(files, cpkg.c_source_flags);
        defer fileList.deinit();
    }
    exe.linkLibC();
}

/// add c package delay
const AddDeps = struct {
    step: std.Build.Step,
    exe: *std.Build.LibExeObjStep,
    packages: []const CPackage,
    fn create(owner: *std.Build, exe: *std.Build.LibExeObjStep, packages: []const CPackage) *AddDeps {
        const self = owner.allocator.create(AddDeps) catch unreachable;

        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .install_artifact,
                .name = owner.fmt("add c deps for {s}", .{exe.name}),
                .owner = owner,
                .makeFn = addDeps,
            }),
            .exe = exe,
            .packages = packages,
        };
        return self;
    }
};
