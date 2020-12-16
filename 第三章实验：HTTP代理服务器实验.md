# 第三章实验：HTTP代理服务器实验
## 1.实验要求
### 实验验证：在Kali Linux（网关）中安装tinyproxy，然后用主机设置浏览器代理指向tinyproxy建立的HTTP正向代理，在Kali中用wireshark抓包，分析抓包过程，理解HTTP正向代理HTTPS流量的特点。
## 2.实验环境
### 实验所需命令行:
```
- -s 可以设置包的最大长度
- 增加host-only方便ssh远程操作
- ps aux | grep apache2 查看apache是否安装
- curl +victim ip地址
- apt update &&apt-get install tinyproxy/apache2/
- tail -F /var/log/apache2/access.log 刷新日志
- -s 可以设置包的最大长度
- 增加host-only的网卡方便ssh远程操作
- ps aux | grep apache2 查看apache是否安装
- curl +victim ip地址
- apt update &&apt-get install tinyproxy/apache2/
- tail -F /var/log/apache2/access.log 刷新日志
```
## 3.实验所需工具:
### tinyproxy
### apache ：web服务器
### curl:cURL是一个利用URL语法在命令行下工作的文件传输工具
## 4.实验步骤
### （1）实验前验证连通性
### （2）攻击者无法ping通靶机，靶机可以ping通攻击者
### （3）攻击者可以上网且可以访问网关
### （4）网关可以ping通攻击者和靶机
## 5.实验过程
### （1）在未开启apache前，靶机对攻击者的HTTP请求没有响应，此时由于web服务器还未开启
### （2）开启apache服务，命令是: systemctl start apache2
### （3）开启apache以后靶机可以通过浏览器访问攻击者
### （4）攻击者仍无法访问靶机
### （5）至此，攻击者还是无法访问靶机，接下来使用正向代理，tinyproxy
#### 网关安装tinyproxy,命令为
```
- apt update && apt-get install tinyproxy //安装tinyproxy
- sudo apt-get install gedit //为使用gedit命令，即编辑配置文件
- vi /etc/tinyproxy/tinyproxy.conf  //编辑配置文件
- service tinyproxy start //开启tinyproxy
```
#### 配置文件允许该网段使用本网关为代理，10.0.0.0/8设置为allow，注意:linux中:wq是保存并退出
### （6）攻击者配置代理，网关设为代理，端口设为默认值8888
### （7）配置完成后，攻击者在浏览器对靶机进行访问，同时在靶机上抓包
```
命令:tcpdump -i eth0 -n -s 65535 -w attacker.pcap //抓包长度限制为65535，并把结果保存下来
```
### （8）攻击者访问靶机的apache，同时让靶机进行抓包，访问两个地址分别为:172.16.111.133和172.16.111.133/nationalday，分别出现apache界面和404
### （9）查看抓包结果,由于本次实验只关心http协议，所以过滤后剩下以下信息
### （10）选取其中404的包追踪http流，发现我们能看到代理，但是看不到具体的信息（ip地址等等信息）
### （11）攻击者访问https并在网关抓包
## 6.实验总结
### （1）本次实验通过设置代理服务器的方式改变了原来网络的连通性，攻击者在未设置代理之前，无法访问靶机，而在经过tinyproxy的设置后，可以进行访问。
### （2）代理服务器可以看到主机访问的网址。
