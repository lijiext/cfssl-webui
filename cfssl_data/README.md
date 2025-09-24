## 生成ROOT CA
```
# 下载 cfssl 和 cfssljson
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssl_1.6.5_linux_amd64 -O cfssl
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssl-certinfo_1.6.5_linux_amd64 -O cfssl-certinfo
wget https://github.com/cloudflare/cfssl/releases/download/v1.6.5/cfssljson_1.6.5_linux_amd64 -O cfssljson

chmod +x cfssl cfssljson cfssl-certinfo

# 生成 Root CA
./cfssl gencert -initca root_ca_csr.json | ./cfssljson -bare root_ca

```