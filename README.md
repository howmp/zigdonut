# zigdonut

用zig实现精简版的donut,可将exe/dll转换为shellcode

## 特性

1. 静态TLS的支持(比如rust的exe/dll)，目前只有IoM/c3/MemoryModulePP等支持部分操作系统
2. 没有重定位表时，会尝试根据ImageBase申请内存
3. 更彻底的擦除，除了擦除PE头之外，还擦除了导入表
4. 通过ollvm生成混淆Loader(暂未公开)

## 编译

需要zig 0.11.0

`zig build`

## 调试

通过loaderxx.exe加载shellcode，根据日志判断问题

### 32位PE

```bash
zigdonut.exe in32.exe instance32
loader32.exe 
```

### 64位PE

```bash
zigdonut.exe in64.exe instance64
loader64.exe 
```


## 实现说明

<https://guage.cool/zig-3-donut.html>