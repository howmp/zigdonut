# zigdonut

用zig实现精简版的donut，可将PE/ELF转换为shellcode

## 特性

### PE (Windows)

1. 静态TLS的支持(比如rust的exe/dll)，目前只有IoM/c3/MemoryModulePP等支持部分操作系统
2. 没有重定位表时，会尝试根据ImageBase申请内存
3. 更彻底的擦除，除了擦除PE头之外，还擦除了导入表

### ELF (Linux x86_64)

1. 支持静态链接的PIE/ET_DYN ELF
2. 完整的ELF loader：段映射、RELATIVE重定位、栈帧构建(auxv)
3. Double fork脱离控制终端，后台执行，不产生僵尸集成
4. 输出重定向到文件
5. 切换工作目录到/tmp

## 编译

需要zig 0.11.0

```bash
zig build
```

产出文件在 `zig-out/bin/` 下：

| 文件 | 说明 |
|------|------|
| `zigdonut` | 生成器，将PE/ELF转为shellcode |
| `elfdebug` | ELF loader调试(独立可执行) |
| `elfscloader` | ELF shellcode加载器(C语言) |
| `pedebugXX.exe` | PE loader调试 |

## 使用

### ELF (Linux)

生成shellcode：

```bash
./zigdonut busybox busybox.sc
```

加载运行shellcode：

```bash
./elfscloader busybox.sc output ps
```

- `busybox.sc` - 生成的shellcode文件
- `output` - 重定向输出文件
- `ps` - 要执行的命令及参数

调试模式（直接加载ELF，不经过shellcode）：

```bash
./elfdebug ps
```

### PE (Windows)

生成shellcode：

```bash
zigdonut.exe input.exe output.sc
```

擦除PE头：

```bash
zigdonut.exe -w input.exe output.sc
```

调试：

```bash
# 32位
zigdonut.exe in32.exe instance32
pedebug32.exe

# 64位
zigdonut.exe in64.exe instance64
pedebug64.exe
```


## 实现说明

<https://guage.cool/zig-3-donut.html>
