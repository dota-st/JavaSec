# JNDI基础

## 初识JNDI

JNDI（Java Name and Directory Interface，Java 命名和目录接口）是一种标准的 Java 命名系统接口，JNDI 提供统一的客户端 API，并由管理者将 JNDI API 映射为特定的**命名服务**和**目录服务**，为开发人员查找和访问各种资源提供了统一的通用接口，可以用来定义用户、网络、机器、对象和服务等各种资源。简单来说，开发人员通过使用 JNDI，可以让用户通过统一的方式访问和获取网络上各种资源和服务，如下图所示：

![1](images/1.png)

这里有两个重要的概念：命名服务（Naming Server）和目录服务（Directory Server）。

### 命名服务

简单来说，命名服务是一种通过名称来查找实际对象的服务，比如我们前面学过的 RMI 协议，就可以通过名称来查找（lookup）并调用具体的远程对象。除此之外，我们经常接触到的 DNS 协议，也是通过域名来查找具体的 IP 地址，这就是命名服务的基本概念。

在 JNDI 的命名服务中，有几个重要的概念需要了解：

- `Bindings`：表示一个名称和对应对象的绑定关系，例如 RMI 中将远程对象绑定到对应的 name 中，DNS 中域名绑定到对应的 IP；
- `Context`：上下文，一个上下文中对应着一组名称和对象的绑定关系。我们可以根据指定上下文中查找名称所对应的对象。以文件系统举例，一个文件夹目录就是一个上下文，我们可以在该目录中查找所需要的文件，其中的子目录也可以称为子上下文（SubContext）；
- `References`：在实际的名称服务中，有些对象可能无法直接存储在系统内，此时可以让这些对象以引用的形式进行存储，类似于 C/C++ 中的指针概念。在引用中包含了获取实际对象所需要的信息，比如 Linux 系统中，根据名称打开的文件是一个 fd（file descriptor），内核根据这个引用值去找到磁盘中对应位置和偏移，这就是引用的一个实际案例。

### 目录服务

目录服务是命名服务的扩展，除了名称服务中已有的名称和对象的关联信息外，还允许对象拥有属性（Attributes）信息。因此，我们除了可以通过名称去查找对象，还可以根据属性值去搜索对象。

以下是一些常见的目录服务：

- `LDAP`：轻型目录访问协议。
- `Active Directory`：为 Windows 域网络设计，包含多个目录服务，比如域服务、证书服务等。
- 其他基于 X.500（目录服务的标准）实现的目录服务。

### JNDI SPI

JNDI 架构上主要包含两个部分，即 Java 的应用层接口和 SPI，如下图所示：

![2](images/2.gif)

SPI（Service Provider Interface）即服务供应接口，主要作用是为底层的具体目录服务提供统一接口，从而实现目录服务的可插拔式安装。

JDK 中包含了下述内置的命名目录服务：

- `RMI`：Java 远程方法调用；
- `LDAP`：轻量级目录访问协议；
- `CORBA`：通用对象请求代理结构（Common Object Request Broker Architecture），用于 COS 名称服务（Common Object Services）；
- `DNS`：域名转换协议。

除了上述所列举的目录服务，还可以在 Java 官网上下载其他的目录服务实现，因为 SPI 的存在，厂商可以提供自己的私有目录服务实现，用户无需重复修改代码。

## JNDI示例

JDK 提供了以下几个包来完成 JNDI 的功能实现：

- `javax.naming`：主要用于命名操作，包含了访问命名服务的类和接口，该包定义了`Context`接口和`InitialContext`类，其中`Context`是查找、绑定/解绑定、重命名对象以及创建和销毁子上下文的核心接口；
- `javax.naming.directory`：主要用于目录操作，定义了`DirContext`接口和`InitialDir-Context`类；
- `javax.naming.event`：用于支持命名和目录服务中的事件通知的类和接口；
- `javax.naming.ldap`：提供 LDAP 服务支持；
- `javax.naming.spi`：允许动态插入不同的实现，为不同命名和目录服务供应商的开发人员可以开发和连接他们的实现的方法，以便可以从使用 JNDI 的应用程序访问相应的服务。

接下来，我们通过具体 demo 来实现 JNDI 与各服务进行交互的效果。

### JNDI_RMI

先把 RMI 服务起好，接口`UserInterface`
```java
package com.rmi.server;

import java.rmi.Remote;

/**
 * Created by dotast on 2023/1/3 17:12
 */
public interface UserInterface extends Remote {
    public Object getUser() throws Exception;

    public void setUser(Object user) throws Exception;
}
```

`UserClass`类

```java
package com.rmi.server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * Created by dotast on 2023/1/3 17:14
 */
public class UserClass extends UnicastRemoteObject implements UserInterface {

    protected UserClass() throws RemoteException {
    }

    @Override
    public String getUser() throws Exception{
        System.out.println("调用getUser方法成功");
        Runtime.getRuntime().exec("open -a Calculator.app");
        return "dotast";
    }

    @Override
    public void setUser(Object user) throws Exception {
        System.out.println("调用setUser方法成功");
    }
}

```

`RmiServer`类

```java
package com.rmi.server;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Created by dotast on 2023/1/3 17:13
 */
public class RmiServer {
    public static void main(String[] args) throws RemoteException {
        // 创建远程对象
        UserInterface userClass = new UserClass();
        // 创建RMI Registry(注册表)
        Registry registry = LocateRegistry.createRegistry(1099);
        // 将远程对象注册到注册表,设置名称
        registry.rebind("user", userClass);
        System.out.println("RMI Server start...");
    }
}
```

启动服务端
![image-20230128153521104](images/image-20230128153521104.png)

开始编写`JNDI_RMI`类，通过 JNDI 接口调用远程对象方法
```java
package com.jndi;

import com.rmi.server.UserInterface;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.util.Hashtable;

/**
 * Created by dotast on 2023/1/28 15:35
 */
public class JNDI_RMI {
    public static void main(String[] args) throws Exception{
        // 设置 JNDI 环境变量
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        //初始化上下文
        InitialContext initialContext = new InitialContext(env);
        // 调用远程类
        UserInterface userInterface = (UserInterface) initialContext.lookup("user");
        userInterface.getUser();
    }
}
```

运行后成功调用到远程对象的`getUser()`方法，弹出计算器
![image-20230128154249151](images/image-20230128154249151.png)

### JNDI_DNS

以 JDK 内置的 DNS 目录服务为例：
```java
package com.jndi;

import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Created by dotast on 2023/1/28 15:50
 */
public class JNDI_DNS {
    public static void main(String[] args) throws Exception{
        // 设置JNDI环境变量
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        env.put(Context.PROVIDER_URL, "dns://192.168.0.1");

        DirContext dirContext = new InitialDirContext(env);
        Attributes attribute = dirContext.getAttributes("github.com", new String[]{"A"});
        System.out.println(attribute);
    }
}
```

运行结果
![image-20230128155747280](images/image-20230128155747280.png)

## JNDI的工作流程

在前面我们通过 JNDI 成功调用了 RMI 和 DNS 的服务，过程也很简单，初始化`Context`后，接着通过`Context`来与服务进行交互。

我们以 RMI 的 demo 为例进行说明
```java
package com.jndi;

import com.rmi.server.UserInterface;

import javax.naming.Context;
import javax.naming.InitialContext;
import java.util.Hashtable;

/**
 * Created by dotast on 2023/1/28 15:35
 */
public class JNDI_RMI {
    public static void main(String[] args) throws Exception{
        // 设置 JNDI 环境变量
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
        //初始化上下文
        InitialContext initialContext = new InitialContext(env);
        // 调用远程类
        UserInterface userInterface = (UserInterface) initialContext.lookup("user");
        userInterface.getUser();
    }
}
```

一开始，通过`Hashtable`创建了一个哈希表，然后设置`Context.INITIAL_CONTEXT_FACTORY`和`Context.PROVIDER_URL`属性的键值对。

通过`Context.INITIAL_CONTEXT_FACTORY`属性的值`com.sun.jndi.rmi.registry.RegistryContextFactory`让 JNDI 调用 RMI 服务，而`Context.PROVIDER_URL`属性则提供给 JNDI 要调用的服务的地址。

接着通过我们设置好的属性值初始化`InitialContext`类，获得一个与 RMI 服务相关联的上下文`initialContext`。我们来看看`InitialContext`类的构造函数
![image-20230128161059926](images/image-20230128161059926.png)

可以看到`InitialContext`类不止一种初始化方式。接下来看看与服务交互的方式，其实并不陌生
![image-20230128161426871](images/image-20230128161426871.png)

和前面学习过的 RMI 一样，这里就不再赘述，忘记的就回去看看 RMI 的交互方式。

## JNDI的底层实现

正在更新中...
