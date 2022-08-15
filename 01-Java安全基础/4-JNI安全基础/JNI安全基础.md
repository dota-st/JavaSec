# JNI安全基础

## 前言

Java 语言是基于 C 语言实现，并且 Java 底层的很多 API 都是通过`JNI(Java Native Interface)`来实现的。`JNI`的作用是可以通过 Java 程序去调用 C 的程序（调用的是编译好的 DLL 动态链接库里的方法）。

## JNI实现

JNI 的实现大致分为以下步骤：
```
1.定义一个 native 修饰的方法
2.使用 javah 进行编译
3.编写 C 代码
4.编译成动态链接库
5.编写 Java 类并加载动态链接库进行调用
```

### 定义native方法

```java
package com.dotast;

/**
 * Created by dotast on 2022/8/15 21:26
 */
public class JNIExec {
    public static native String exec (String cmd);
}
```

### 使用javah进行编译

**注意JDK版本：**

JDK 10 移除了`javah`,需要改为`javac`加`-h`参数的方式生产头文件，如果 JDK 版本正好`>=10`,那么使用如下方式可以同时编译并生成头文件。
```bash
 javac -cp . com/dotast/JNIExec.java -h com/dotast/
```

当前目录生成`.class`文件和`.h`头文件
![image-20220815213424319](JNI安全基础.images/image-20220815213424319.png)

![image-20220815214055565](JNI安全基础.images/image-20220815214055565.png)

其中的`Java_com_dotast_JNIExec_exec`前面的`Java`是固定的，后面则是类名和方法名。

括号里面的参数`JNIEnv`是`JNI`环境变量对象，`jclass`是`java`调用的对象，后面则是传入的参数类型。该文件是后面编写 C 代码的时候导入的头文件。

### 编写C代码

`com_dotast_JNIExec.cpp`源代码

```cpp
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include "com_dotast_JNIExec.h"

using namespace std;

JNIEXPORT jstring

JNICALL Java_com_dotast_JNIExec_exec
        (JNIEnv *env, jclass jclass, jstring str) {

    if (str != NULL) {
        jboolean jsCopy;
        // 将jstring参数转成char指针
        const char *cmd = env->GetStringUTFChars(str, &jsCopy);

        // 使用popen函数执行系统命令
        FILE *fd  = popen(cmd, "r");

        if (fd != NULL) {
            // 返回结果字符串
            string result;

            // 定义字符串数组
            char buf[128];

            // 读取popen函数的执行结果
            while (fgets(buf, sizeof(buf), fd) != NULL) {
                // 拼接读取到的结果到result
                result +=buf;
            }

            // 关闭popen
            pclose(fd);

            // 返回命令执行结果给Java
            return env->NewStringUTF(result.c_str());
        }

    }

    return NULL;
}
```

### 编译成动态链接库

`MacOS编译:`

```bash
g++ -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" -shared -o libcmd.jnilib com_dotast_JNIExec.cpp
```

`Linux编译:`

```bash
g++ -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -shared -o libcmd.so com_dotast_JNIExec.cpp
```

本人为`MacOS`系统，编译后生成`libcmd.jnilib`文件

### 编写java类并调用动态链接库

```java
package com.dotast;

/**
 * Created by dotast on 2022/8/15 22:02
 */
public class ExecTest {
    public static void main (String[] args){
        System.load("/xxx/dotast/libcmd.jnilib");
        JNIExec jniExec = new JNIExec();
        String cmd = jniExec.exec("open -a Calculator.app");
        System.out.println(cmd);
    }
}

```

![image-20220816000522188](JNI安全基础.images/image-20220816000522188.png)

