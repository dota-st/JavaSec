# JavaSec学习笔记📝

## 碎碎念

一个存储自己学习 Java 安全的笔记仓库，所思随所欲，文笔难掩拙劣，仅供参考。

如果本文也恰好对你有所帮助，不妨留下你的⭐️。

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
│   └── 7-Java字节码
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
│   └── 9-CommonsCollections11
├── 04-shiro专区
│   ├── 0-shiro之CVE-2010-3863
│   ├── 1-shiro之CVE-2016-4437
│   ├── 2-shiro之key的检测
│   └── 3-shiro之CVE-2016-6802
├── 05-内存马专区
│   ├── 0-Tomcat内存马之Listener
│   ├── 1-Tomcat内存马之Filter
│   ├── 2-Tomcat内存马之Servlet
│   └── 3-反序列化注入内存马
├── README.md
├── 环境&其他
│   └── Tomcat源码调试
└── 参考链接.md
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

## Shiro专区

- [CVE-2010-3863（权限绕过）漏洞分析](./04-shiro专区/0-shiro之CVE-2010-3863/CVE-2010-3863.md)
- [CVE-2016-4437（shiro-550）漏洞分析](./04-shiro专区/1-shiro之CVE-2016-4437/CVE-2016-4437.md)
- [shiro 之 key 的检测](./04-shiro专区/2-shiro之key的检测/shiro之key的检测.md)
- [CVE-2016-6802（权限绕过）漏洞分析](./04-shiro专区/3-shiro之CVE-2016-6802/CVE-2016-6802.md)
- 留坑

## 内存马专区

- [Tomcat内存马之Listener](./05-内存马专区/0-Tomcat内存马之Listener/Listener内存马.md)
- [Tomcat内存马之Filter](./05-内存马专区/1-Tomcat内存马之Filter/Filter内存马.md)
- [Tomcat内存马之Servlet](./05-内存马专区/2-Tomcat内存马之Servlet/Servlet内存马.md)
- [反序列化注入内存马](./05-内存马专区/3-反序列化注入内存马/反序列化注入内存马.md)

