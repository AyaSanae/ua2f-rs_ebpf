<div align="center">
  
# **ua2f-rs-ebpf**

### HTTP UA modifier using eBPF
### 基于eBPF实现的HTTP User-Agent修改程序

![Downloads](https://img.shields.io/github/downloads/AyaSanae/%20ua2f-rs_ebpf/total?style=for-the-badge&logo=Rust)

</div>
[什么是eBPF?](https://ebpf.io/what-is-ebpf/#what-is-ebpf)

## 注意！！
### 最小内核版本要求 >= 4.16

因为基于eBPF所以你需要root权限来运行这个程序.

要使用本程序要确保内核支持(使用下面命令检测,如果输出了❌,那么你要自编译内核把相对应的内核选项打开):

请在shell上运行
```
zcat /proc/config.gz 2>/dev/null | awk '
    BEGIN {
        config["CONFIG_BPF"] = "❌";
        config["CONFIG_BPF_SYSCALL"] = "❌";
        config["CONFIG_NET_CLS_BPF"] = "❌";
        config["CONFIG_NET_ACT_BPF"] = "❌";
        config["CONFIG_BPF_JIT"] = "❌";
        config["CONFIG_NET_SCH_INGRESS"] = "❌";
        config["CONFIG_XDP_SOCKETS"] = "❌";
        config["CONFIG_BPF_STREAM_PARSER"] = "❌";
        config["CONFIG_NET_SCHED"] = "❌";
        config["CONFIG_NET_CLS"] = "❌";
    }
    {
        for (cfg in config) {
            if ($0 ~ "^" cfg "[= ]") {
                config[cfg] = "✅";
            }
        }
    }
    END {
        n = asorti(config, sorted);
        for (i = 1; i <= n; i++) {
            print sorted[i] " " config[sorted[i]];
        }
    }'
```

## 快速开始

```
sudo -E ua2f-rs -i eth1 --ttl 64
```

如果是首次运行,本程序会在~/.config生成配置文件,当然你也可以使用-c(--config)来指定配置文件.

attach_iface用于指定附加的接口,filter_ip可以指定被过滤的ip,如果目的ip在filter_ip内那将会直接放行，不会对数据包进行处理.

## 使用帮助

```
Usage: ua2f-rs [OPTIONS]

Options:
  -i, --iface <IFACE>      
  -c, --config <CONFIG>    
      --ttl <TTL>          
      --verbose <VERBOSE>  [possible values: true, false]
  -h, --help               Print help
  -V, --version            Print version
```

## 配置文件

启动时程序传入的参数优先级比文件高但,不会覆写配置文件.

fliter_ip只支持和IPv4单地址和IPv4 CIDR网段格式.(不支持IPv6)

最多支持114个单地址和114个CIDR网段

### config.toml
```
attach_iface = "eth1"
filter_ip = [
    "0.0.0.0/8",        
    "10.0.0.0/8",       
    "100.64.0.0/10",    
    "127.0.0.0/8",      
    "169.254.0.0/16",   
    "172.16.0.0/12",    
    "192.168.0.0/16",   
    "224.0.0.0/4"       
]
ttl = 64
```

## 特性
安全,快速,易于使用.

自定义TTL.

统计修改的HTTP包数量.

## 编译

更多细节请看: [Aya build env](https://aya-rs.dev/book/start/development/#prerequisites)

```
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
git clone https://github.com/AyaSanae/ua2f-rs_ebpf && cd ua2f-rs_ebpf
cargo build --release
```

## 测试

在 EndeavourOS Linux x86_64(CPU:AMD R7 5800H)(内核版本6.14.2-arch1-1) 上测试正常运行.

在香橙派3B Ubuntu 22.04.4 LTS aarch64 (CPU:RK3566)（内核版本5.10)上测试正常运行.


简单压力测试:

香橙派3B作为客户端,附加ua2f-rs_ebpf到局域网接口,服务器运行miniserve守候,通过千兆线连接

客户端使用wrk测试,ua2f-rs_ebpf附加前:

```
wrk -t4 -c200 -d60s -H "User-Agent: 11451419198100x11451419198101145140x114" http://192.168.2.7:8000
```

结果:

```
Running 1m test @ http://192.168.2.7:8000
  4 threads and 200 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    19.72ms    6.41ms 359.83ms   70.76%
    Req/Sec     2.55k   200.14     2.93k    68.17%
  609735 requests in 1.00m, 5.00GB read
Requests/sec:  10150.28
Transfer/sec:     85.20MB
```

ua2f-rs_ebpf附加后:

```
wrk -t4 -c200 -d60s -H "User-Agent: 11451419198100x11451419198101145140x114" http://192.168.2.7:8000
```

结果:

```
Running 1m test @ http://192.168.2.7:8000
  4 threads and 200 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    23.00ms   23.27ms 472.93ms   97.03%
    Req/Sec     2.46k   338.85     4.65k    63.55%
  588140 requests in 1.00m, 4.82GB read
Requests/sec:   9789.16
Transfer/sec:     82.16MB
```

## LICENSE
[GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.txt)
