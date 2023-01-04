# RMI

## 初识RMI

RMI（Remote Method Invocation）即 Java 远程方法调用，能够让一台 Java 虚拟机上的对象调用另一台运行中的 Java 虚拟机上的对象的方法，实现 Java 程序之间跨 JVM 的远程通信。该远程方法调用是分布式编程的基本思想之一，可以使客户端上的程序调用远程服务端上的对象。

RMI 使用的通信协议为 JRMP（Java Remote Message Protocol ，Java 远程消息交换协议），类似于传统的 HTTP 协议，规定了通信双方需要满足的规范。在 RMI 中，对象通过序列化的方式进行传输，这也是能造成反序列化攻击的条件之一。

从设计角度看，RMI分为三层架构模式：RMI 客户端、RMI 服务端和 RMI 注册中心：

- RMI-客户端：客户端调用服务端上的对象方法；
- RMI-服务端：为客户端提供调用的对象方法，一般执行完成后给客户端返回对应的方法执行结果；
- RMI-注册中心：本质上为一个 Map，给客户端提供需要调用方法的引用（需要特别注意的是，在低版本 JDK 中，服务端和注册中心可以不用在同一台服务器上；但在高版本的 JDK 中，服务端和注册中心必须在同一台服务器上，否则会注册失败）。

## RMI对象调用

前面我们知道，RMI 的出现解决了Java 程序之间跨 JVM 的远程通信问题，那么它是如何从 JVM A（客户端）访问JVM B（服务端）上的对象呢？

首先，RMI 将一个远程对象的 Stub（存根）传递给客户端，Stub 相当于远程对象的引用或者代理。对于开发者，Stub 是透明的，客户端可以像调用本地方法一样直接通过它来调用远程方法。Stub 包含了远程对象的定位信息，比如 Socket 端口和服务端的主机地址等等，除此之外还实现了远程调用过程中具体的底层网络通信细节。

位于服务端的 Skeleton（骨架）能够读取客户端传递的方法参数，从而调用服务端上对应的对象方法，最后接收对象方法执行完后的返回结果。以下是简单的 RMI 远程对象调用逻辑图：

![图片-80](images/图片-80.png)

从上图中我们可以看到，实际的通信过程是：客户端 --> Stub --> Skeleton --> 服务端，具体的通信过程为：

- 服务端监听一个端口，端口为 JVM 随机指定；
- 客户端从 Stub 获取到服务端远程对象的通信地址和端口，客户端可以调用 Stub 上的具体方法和发送具体的方法参数；
- Stub 连接到服务端上监听的 Socket 端口并提交方法参数；
- 服务端执行具体的对象方法，并将结果返回到 Stub；
- Stub 再将执行结果返回到客户端上。

弄清楚了 RMI 远程对象方法调用的流程，还有一个问题我们需要关心，即 Stub 是如何获取到远程服务端的通信信息？

接下来引出下一个主角：RMI Registry。

## RMI Registry

为了解决我们上面说的问题，JDK 提供了 RMI Registry（RMI注册表）。RMI Registry 也是一个远程对象，监听端口默认为 1099。

下面是一个 RMI Registry 的注册 demo：
```java
// 创建远程对象
HelloInterface helloClass = new HelloClass();
// 创建RMI Registry(注册表)
Registry registry = LocateRegistry.createRegistry(1099);
// 将远程对象注册到注册表,设置名称为hello
registry.rebind("hello", helloClass);
System.out.println("RMI Server start...");
```

完成了 RMI Registry 的注册之后，我们编写一个简单的 RMI 客户端 demo 调用：
```java
public class RmiClient {
    public static void main(String[] args) throws RemoteException, NotBoundException {
        //获取远程主机对象
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);
        // 在注册表中查询名称为hello的对象
        HelloInterface helloClass = (HelloInterface) registry.lookup("hello");
        // 调用远程对象hello的方法
        System.out.println(helloClass.sayHello());
    }
}
```

在该 demo 中，通过`LocateRegistry.getRegistry()`方法在客户端本地创建一个 Stub 对象作为 Registry 远程对象的代理，随后客户端可以从 RMI 注册表中查询某个远程对象的名称，获取该远程对象的 Stub。

引入 RMI Registry 后，RMI 更详细的调用关系如下图所示：

![20210120142055-a6f63ab2-5ae7-1](images/20210120142055-a6f63ab2-5ae7-1.png)

## RMI客户端与服务端

下面我们通过一个简单的示例代码完成 RMI 的客户端与服务端通信过程。

服务端--编写`HelloInterface`接口：

- 需要使用 public 声明；
- 需要继承于 Remote 类；
- 接口类的方法需要声明`java.rmi.RemoteException`异常；

```java
package com.rmi.server;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * Created by dotast on 2023/1/3 17:12
 */
public interface HelloInterface extends Remote {
    public String sayHello() throws RemoteException;
}
```

服务端--编写接口实现类`HelloClass`：

- 实现接口类；
- 继承于`UnicastRemoteObject`类，不继承的话则需要手工初始化远程对象，在构造方法调用`UnicastRemoteObject.exportObject()`静态方法；
- 方法（包括构造方法）需要声明`java.rmi.RemoteException`异常；
- 实现类中使用的对象需要继承于`java.io.Serializable`接口以支持序列化，并且客户端的`serialVersionUID`属性值要与服务器端保持一致；

```java
package com.rmi.server;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

/**
 * Created by dotast on 2023/1/3 17:14
 */
public class HelloClass extends UnicastRemoteObject implements HelloInterface {

    protected HelloClass() throws RemoteException {
    }

    @Override
    public String sayHello() throws RuntimeException {
        System.out.println("hello, dotast");
        return "hello, dotast";
    }
}
```

服务端--编写`RmiServer`类注册远程对象到注册表中
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
        HelloInterface helloClass = new HelloClass();
        // 创建RMI Registry(注册表)
        Registry registry = LocateRegistry.createRegistry(1099);
        // 将远程对象注册到注册表,设置名称为hello
        registry.rebind("hello", helloClass);
        System.out.println("RMI Server start...");
    }
}
```

客户端--编写`RmiClient`类调用服务端上的远程对象方法
```java
package com.rmi.client;

import com.rmi.server.HelloInterface;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Created by dotast on 2023/1/4 16:39
 */
public class RmiClient {
    public static void main(String[] args) throws RemoteException, NotBoundException {
        //获取远程主机对象
        Registry registry = LocateRegistry.getRegistry("127.0.0.1",1099);
        // 在注册表中查询名称为hello的对象
        HelloInterface helloClass = (HelloInterface) registry.lookup("hello");
        // 调用远程对象hello的方法
        System.out.println(helloClass.sayHello());
    }
}
```

先运行服务端，然后在运行客户端完成一次调用流程。

服务端运行结果：
![image-20230104173658873](images/image-20230104173658873.png)

客户端运行结果：
![image-20230104173709678](images/image-20230104173709678.png)

客户端成功调用服务端上的远程对象`HelloClass`的`sayHello()`方法。

## 通过源码分析RMI流程

待补充