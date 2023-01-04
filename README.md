# JavaSec学习笔记📝

## 碎碎念

一个存储自己学习 Java 安全的笔记仓库，所思随所欲，文笔难掩拙劣，仅供参考。

如果本文也恰好对你有所帮助，不妨留下你的⭐️。



一些拖更的原因（借口）：

- 新冠患者🤒（ing）
- ....

## 目录

```
.
├── 00-JavaSE
│   ├── 0-java程序基础知识
│   ├── 1-java面向对象编程
│   ├── 2-反射
│   ├── 3-动态代理
│   └── 4-注解
├── 01-JavaWeb基础
│   ├── 0-Servlet
│   ├── 1-Jsp
│   ├── 2-Filter
│   └── 3-Listener
├── 02-Java安全基础
│   ├── 0-反射
│   ├── 1-类加载机制
│   ├── 2-Java文件系统
│   ├── 3-Java命令执行
│   ├── 4-JNI安全基础
│   ├── 5-Java反序列化
│   ├── 6-JShell
│   ├── 7-Java字节码
│   └── 8-RMI
├── 03-反序列化专区
│   ├── 0-URLDNS利用链
│   ├── 1-CommonsCollections
│   ├── 2-CommonsCollections1
│   ├── 3-CommonsCollections6
│   ├── 4-CommonsCollections2
│   ├── 5-CommonsCollections3
│   ├── 6-CommonsCollections4
│   ├── 7-CommonsCollections5
│   ├── 8-CommonsCollections7
│   ├── 9-CommonsCollections11
│   ├── 10-探寻新CC利用链之旅(上)
│   ├── 11-探寻新CC利用链之旅(下)
│   └── 12-CommonsBeanutils
├── 04-Shiro专区
│   ├── 0-Shiro之CVE-2010-3863
│   ├── 1-Shiro之CVE-2016-4437
│   ├── 2-Shiro之key的检测
│   ├── 3-Shiro自身反序列化利用链
│   └── 4-Shiro之CVE-2016-6802
├── 05-内存马专区
│   ├── 0-Tomcat内存马之Listener
│   ├── 1-Tomcat内存马之Filter
│   ├── 2-Tomcat内存马之Servlet
│   ├── 3-反序列化注入内存马
│   ├── 4-Spring内存马之Controller
│   └── 5-Spring内存马之Interceptor
├── 06-FastJson专区
│   └── 0-FastJson-1.2.24
├── README.md
├── 参考链接.md
├── 比赛专区
│   └── 2022祥云杯--ezjava
└── 环境&其他
    └── Tomcat源码调试
```

## 环境&其他

- [Tomcat源码调试](./环境&其他/Tomcat源码调试/Tomcat源码调试.md)

## 反序列化专区

- [Java反序列化基础](./02-Java安全基础/5-Java反序列化/Java反序列化.md)
- [URLDNS利用链分析](./03-反序列化专区/0-URLDNS利用链/URLDNS利用链.md)
- [CommonsCollections 利用链分析](./03-反序列化专区/1-CommonsCollections/CommonsCollections.md)
- [CommonsCollections1 利用链分析](./03-反序列化专区/2-CommonsCollections1/CommonsCollections1.md)
- [CommonsCollections6 利用链分析](./03-反序列化专区/3-CommonsCollections6/CommonsCollections6.md)
- [CommonsCollections2 利用链分析](./03-反序列化专区/4-CommonsCollections2/CommonsCollections2.md)
- [CommonsCollections3 利用链分析](./03-反序列化专区/5-CommonsCollections3/CommonsCollections3.md)
- [CommonsCollections4 利用链分析](./03-反序列化专区/6-CommonsCollections4/CommonsCollections4.md)
- [CommonsCollections5 利用链分析](./03-反序列化专区/7-CommonsCollections5/CommonsCollections5.md)
- [CommonsCollections7 利用链分析](./03-反序列化专区/8-CommonsCollections7/CommonsCollections7.md)
- [CommonsCollections11 利用链分析](./03-反序列化专区/9-CommonsCollections11/CommonsCollections11.md)
- [探寻新CC利用链之旅(上)](./03-反序列化专区/10-探寻新CC利用链之旅(上)/index.md)
- [探寻新CC利用链之旅(下)](./03-反序列化专区/11-探寻新CC利用链之旅(下)/index.md)
- [CommonsBeanutils利用链分析](./03-反序列化专区/12-CommonsBeanutils/index.md)

## Shiro专区

- [CVE-2010-3863（权限绕过）漏洞分析](./04-Shiro专区/0-Shiro之CVE-2010-3863/index.md)
- [CVE-2016-4437（Shiro-550）漏洞分析](./04-Shiro专区/1-Shiro之CVE-2016-4437/index.md)
- [Shiro之 key 的检测](./04-Shiro专区/2-Shiro之key的检测/index.md)
- [Shiro自身反序列化利用链](./04-Shiro专区/3-Shiro自身反序列化利用链/index.md)
- [CVE-2016-6802（权限绕过）漏洞分析](./04-Shiro专区/4-Shiro之CVE-2016-6802/index.md)

## 内存马专区

- [Tomcat内存马之Listener](./05-内存马专区/0-Tomcat内存马之Listener/Listener内存马.md)
- [Tomcat内存马之Filter](./05-内存马专区/1-Tomcat内存马之Filter/Filter内存马.md)
- [Tomcat内存马之Servlet](./05-内存马专区/2-Tomcat内存马之Servlet/Servlet内存马.md)
- [反序列化注入内存马](./05-内存马专区/3-反序列化注入内存马/反序列化注入内存马.md)
- [Spring内存马之Controller](./05-内存马专区/4-Spring内存马之Controller/Controller内存马.md)
- [Spring内存马之Interceptor](./05-内存马专区/5-Spring内存马之Interceptor/Interceptor内存马.md)

## FastJson专区

- [FastJson-1.2.24 利用链分析](./06-FastJson专区/0-FastJson-1.2.24/index.md)

## 比赛专区

这里会记录一些比赛中用到的，有关正在学习的 Java 知识点的文章，以作为所学实践。

- [2022 祥云杯 -- ezjava（cc链 + Tomcat全局回显/Spring内存马）](./比赛专区/2022祥云杯--ezjava/index.md)
