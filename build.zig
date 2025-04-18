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
                .name = "loader" ++ t[1],
                .root_source_file = .{ .path = "src/peloader.zig" },
                .target = target,
                .optimize = .ReleaseSmall,
            });
            exe.single_threaded = true;
            b.installArtifact(exe);
        }
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
    {
        const gen = b.addExecutable(.{
            .name = "zigdonut",
            .root_source_file = .{ .path = "src/generator.zig" },
            .target = std.zig.CrossTarget.parse(.{ .arch_os_abi = "x86-windows-gnu" }) catch unreachable,
            .optimize = .ReleaseSmall,
        });
        var d = AddDeps.create(b, gen, genCpackages);
        gen.step.dependOn(&d.step);
        gen.step.dependOn(peloaders_step);
        b.installArtifact(gen);
    }
}

const win32 = @import("src/struct.zig");

fn getNt(base: *anyopaque) *anyopaque {
    var dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    return @ptrFromInt(@intFromPtr(base) + @as(u32, @bitCast(dos.e_lfanew)));
}

fn rva2ofs(comptime T: type, base: *anyopaque, rva: usize, is64: bool) T {
    var nt = getNt(base);

    var sh: [*c]win32.IMAGE_SECTION_HEADER = undefined;
    var shNum: usize = 0;
    if (is64) {
        var nt64: *win32.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
        sh = @ptrFromInt(@intFromPtr(&nt64.OptionalHeader) + nt64.FileHeader.SizeOfOptionalHeader);
        shNum = nt64.FileHeader.NumberOfSections;
    } else {
        var nt32: *win32.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
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
            var nt64: *win32.IMAGE_NT_HEADERS64 = @alignCast(@ptrCast(nt));
            rva = nt64.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            var nt32: *win32.IMAGE_NT_HEADERS32 = @alignCast(@ptrCast(nt));
            rva = nt32.OptionalHeader.DataDirectory[win32.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }

        std.debug.assert(rva != 0);
        var exp = rva2ofs(*win32.IMAGE_EXPORT_DIRECTORY, inst.ptr, rva, is64);
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
