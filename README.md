# LSM Hook JSON Mock Demo

它用 C 语言模拟并解析以下 3 个 SELinux hook 的输入参数和返回值：

- `static int selinux_inode_permission(struct inode *inode, int mask)`
- `static int selinux_file_open(struct file *file)`
- `static int selinux_file_permission(struct file *file, int mask)`

程序会在当前目录创建测试文件，构造语义对齐的 mock `struct inode`、`struct file`、`current task/cred`，然后输出最终 JSON。JSON 中包含：

- `subject`
  - `pid`、`tid`、`scontext`、`comm`
- `request`
  - `mask_raw`、`obj_type`、`perm`
- `target`
  - `dev`、`ino`、`type`、`path`、`tclass`、`tcontext`
- `result`
  - `ret`、`runtime_result`、`policy_result`

补充说明：

- `obj_type` 和 `type` 由 `inode->i_mode` 解码
- `perm` 会结合对象类型和 `mask` 解析，多权限使用 `|` 连接
- `O_APPEND + MAY_WRITE` 会被解释成 `append`
- 如果当前环境拿不到真实 SELinux context，会退化成 mock context

## 使用

编译：

```bash
cd ./lsm-hook-analysis
make
```

运行：

```bash
./hook_json_mock_demo
```

程序运行时会临时生成 `mock-fixtures/` 目录作为测试输入。

## 测试

执行：

```bash
make test
```

这个测试会：

- 编译程序
- 运行程序
- 用 `python3` 校验输出是合法 JSON
- 打印第一条事件的 `hook` 字段作为通过标记

如果你想手动查看完整输出，可以直接运行：

```bash
./hook_json_mock_demo
```

## 清理

删除编译产物：

```bash
make clean
```
