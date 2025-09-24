# CA证书管理工具

## 功能

- 导入/生成根证书
- 图形化的生成服务器证书
- 导出证书

## 使用方法

```
# 1. 编辑cfssl_data中的root_ca_csr.json
你可能需要下载符合你架构和版本的cfssl组件

# 2. 生成根证书
make root

# 3. 启动服务
make up

# 4. 签发服务器证书
访问localhost:8000填写信息即可
```
