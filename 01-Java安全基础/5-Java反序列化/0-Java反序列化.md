# Java反序列化

## 前言

Java对象序列化指的是：将一个Java类实例序列化成字节数组，用于存储对象实例化信息：类成员变量和属性值。 

Java反序列化可指的是：将序列化后的二进制数组转换为对应的Java类实例。

Java序列化对象因其可以方便的将对象转换成字节数组，又可以方便快速的将字节数组反序列化成Java对象而被非常频繁的被用于`Socket`传输。

## 序列化与反序列化

### 概念

在 Java 中，通过`java.io.Serializable(内部序列化)`或者`java.io.Externalizable(外部序列化)`接口即可实现序列化，其中的`java.io.Externalizable`接口只是实现了`java.io.Serializable`接口。

序列化类对象时必须满足以下条件：

- 该类必须实现` java.io.Serializable`接口。
- 该类的所有属性必须是可序列化的(用transient关键字修饰的属性除外，不参与序列化过程)，如果有某个属性不可序列化，则需要注明该属性是短暂的。

反序列化类对象时有如下限制：

- 被反序列化的类必须存在。
- `serialVersionUID`必须一致。

此外，**反序列化类对象不会调用该类的构造方法**。因为在反序列化创建类实例的时候使用了`sun.reflect.ReflectionFactory.newConstructorForSerialization`创建了一个反序列化专用的`Constructor(反射构造方法对象)`，这个特殊的`Constructor`可以绕过构造方法去创建类实例。

编写`User`类
```java
package com.serialize;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class User {
    private String name;
    public  User(){
    }
    public String getName(){
        return name;
    }
    public void setName(String name){
        this.name=name;
    }
}

```

使用反序列化创建`User`类实例
```java
package com.serialize;

import sun.reflect.ReflectionFactory;

import java.lang.reflect.Constructor;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class ReflectionFactoryTest {
    public static void main(String[] args){
        try{
            // 获取sun.reflect.ReflectionFactory对象
            ReflectionFactory factory = ReflectionFactory.getReflectionFactory();
            // 使用反序列化获取User类的构造方法
            Constructor constructor = factory.newConstructorForSerialization(
                    User.class, Object.class.getConstructor()
            );
            System.out.println(constructor.newInstance());
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
```

![image-20220829150934435](images/image-20220829150934435.png)

### 核心方法

`java.io.ObjectOutputStream`类最核心的方法是`writeObject`方法，即序列化类对象。

`java.io.ObjectInputStream`类最核心的功能是`readObject`方法，即反序列化对象。

通过`ObjectInputStream`和`ObjectOutputStream`类我们就可以实现类的序列化和反序列化功能。

**对象序列化步骤如下：**

1. 创建对象输出流
2. 通过输出流的`writeObject()`方法将对象进行序列化

**对象反序列化步骤如下：**

1. 创建一个对象输入流
2. 通过输入流的`readObject()`方法将字节序列反序列化为对象

**代码示例：**

创建`User`类
```java
package com.serialize;

import java.io.Serializable;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class User implements Serializable {
    private String name;
    public  User(){
    }
    public String getName(){
        return name;
    }
    public void setName(String name){
        this.name=name;
    }
}
```

创建`Main`主类
```java
package com.serialize;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Created by dotast on 2022/8/29 15:24
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Main m = new Main();
        m.serialize();
        m.unserialize();
    }

    public void serialize() throws Exception{
        // 创建并实例化文件输出流
        FileOutputStream fileOutputStream = new FileOutputStream("1.txt");
        // 创建并实例化对象输出流
        ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
        User user = new User();
        user.setName("dotast");
        // 通过writeObject方法将类对象进行序列化
        out.writeObject(user);
        System.out.println("serialize success!");
    }

    public void unserialize() throws Exception{
        // 创建并实例化文件输入流
        FileInputStream fileInputStream = new FileInputStream("1.txt");
        // 创建并实例化对象输入流
        ObjectInputStream in = new ObjectInputStream(fileInputStream);
        User user = (User) in.readObject();
        System.out.println("unserialize success!");
        System.out.println("The name is："+user.getName());
        in.close();
    }
}
```

![image-20220829154016718](images/image-20220829154016718.png)

`java.io.Serializable`是一个空的接口，实现该接口的作用是用于**标识该类可序列化**。实现了`java.io.Serializable`接口的类原则上都需要产生一个`serialVersionUID`常量，反序列化时如果双方的`serialVersionUID`不一致会导致`InvalidClassException`异常。如果可序列化类未显示声明`serialVersionUID`，则序列化运行时将基于该类的各个方面计算默认`serialVersionUID`值。

`ObjectOutputStream`序列化类对象的主要流程是首先判断序列化的类是否重写了`writeObject`方法，如果重写了就调用序列化对象自身的`writeObject`方法序列化。`ObjectInputStream`也是同理

**代码示例：**

创建`User`类并重写`writeObject`方法
```java
package com.serialize;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class User implements Serializable {
    private String name;
    public  User(){
    }
    public String getName(){
        return name;
    }
    public void setName(String name){
        this.name=name;
    }

    private void writeObject(ObjectOutputStream out) throws Exception{
        // 先调用默认的writeObject方法
        out.defaultWriteObject();

        // 以下为重写命令执行内容
        Process process = Runtime.getRuntime().exec("ls");
        InputStream in = process.getInputStream();
        ByteArrayOutputStream byte_arr_out = new ByteArrayOutputStream();
        byte[] b = new byte[1024];
        int a = -1;

        //读取命令执行结果流
        while ((a = in.read(b))!= -1){
            byte_arr_out.write(b, 0, a);
        }
        //打印命令执行结果
        System.out.println(byte_arr_out.toString());
    }
}
```

创建`main`主类
```java
package com.serialize;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Created by dotast on 2022/8/29 15:24
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Main m = new Main();
        m.serialize();
        m.unserialize();
    }

    public void serialize() throws Exception{
        // 创建并实例化文件输出流
        FileOutputStream fileOutputStream = new FileOutputStream("1.txt");
        // 创建并实例化对象输出流
        ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
        User user = new User();
        user.setName("dotast");
        // 通过writeObject方法将类对象进行序列化
        out.writeObject(user);
        System.out.println("serialize success!");
    }

    public void unserialize() throws Exception{
        // 创建并实例化文件输入流
        FileInputStream fileInputStream = new FileInputStream("1.txt");
        // 创建并实例化对象输入流
        ObjectInputStream in = new ObjectInputStream(fileInputStream);
        User user = (User) in.readObject();
        System.out.println("unserialize success!");
        System.out.println("The name is："+user.getName());
        in.close();
    }
}
```

![image-20220829162019434](images/image-20220829162019434.png)

运行后，除了正常对类对象的序列化与反序列化之外，还执行了我们重写的`writeObject`方法里的命令执行代码。

这也是反序列化漏洞的成因，如果输入的反序列化数据可以被用户控制，那么攻击者就可以构造恶意的 payload 执行系统命令。

### java.io.Externalizable

`java.io.Externalizable`和`java.io.Serializable`几乎一样，只是`java.io.Externalizable`接口定义了`writeExternal`和`readExternal`方法需要序列化和反序列化的类实现，其余则和`java.io.Serializable`一样。

创建`User`类
```java
package com.serialize;

import java.io.*;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class User implements Externalizable {
    private String name;
    public  User(){
    }
    public String getName(){
        return name;
    }
    public void setName(String name){
        this.name=name;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(name);
    }

    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        this.name = (String) in.readObject();
    }
}

```

主类`Main`和前面一样保持不变
![image-20220829170100690](images/image-20220829170100690.png)

## 常见的魔术方法

实现了`java.io.Serializable`接口的类，可以定义如下方法（反序列化魔术方法），这些方法将会在类序列化或反序列化过程中进行调用：

- `private void writeObject(ObjectOutputStream out)`，自定义序列化
- `private void readObject(ObjectInputStream in)`，自定义反序列化
- `private void readObjectNoData()`
- `protected Object writeReplace()`
- `protected Object readResolve() `

有些方法在前面已经了解和使用过，说说`writeReplace()`和`readResolve()`方法

`writeReplace()`：返回一个对象，该对象为实际被序列化的对象，在原对象序列化之前被调用，替换原对象成为待序列化对象

`readResolve()`：返回一个对象，该对象为实际反序列化的结果对象，在原对象反序列化之后被调用，不影响原对象的反序列化过程，仅替换结果

**代码示例：**

创建`User`类
```java
package com.serialize;

import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Created by dotast on 2022/8/29 11:49
 */
public class User implements Serializable {
    protected String name;

    private void readObject(ObjectInputStream in) throws Exception{
        in.defaultReadObject();
    }
    public User(){
        this.name = "dotast";
    }
    public String getName(){
        return name;
    }

    protected Object readResolve(){
        return new User("admin");
    }
    private User(String name){
        this.name = name;
    }
}
```

创建`Admin`类
```java
package com.serialize;

import java.io.Serializable;

/**
 * Created by dotast on 2022/8/29 17:25
 */
public class Admin implements Serializable {
    protected Object writeReplace(){
        return new User();
    }
}
```

创建主类`Main`
```java
package com.serialize;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * Created by dotast on 2022/8/29 15:24
 */
public class Main {
    public static void main(String[] args) throws Exception {
        Main m = new Main();
        m.serialize();
        m.unserialize();
    }

    public void serialize() throws Exception{
        // 创建并实例化文件输出流
        FileOutputStream fileOutputStream = new FileOutputStream("1.txt");
        // 创建并实例化对象输出流
        ObjectOutputStream out = new ObjectOutputStream(fileOutputStream);
        Admin admin = new Admin();
        // 通过writeObject方法将类对象进行序列化
        out.writeObject(admin);
        System.out.println("serialize success!");
    }

    public void unserialize() throws Exception{
        // 创建并实例化文件输入流
        FileInputStream fileInputStream = new FileInputStream("1.txt");
        // 创建并实例化对象输入流
        ObjectInputStream in = new ObjectInputStream(fileInputStream);
        User user = (User) in.readObject();
        System.out.println("unserialize success!");
        System.out.println("The name is："+user.getName());
        in.close();
    }
}
```

运行结果：
![image-20220829180709106](images/image-20220829180709106.png)

可以看到，在进行序列化的时候，本来序列化的是`Admin`类，由于`writeReplace()`方法的存在变成了序列化`User`类；而`User`类中定义的`name`为变量的值为`dotast`，在进行反序列化的时候，由于`readResolve()`方法的存在，`name`变量的值替换成了`admin`。

