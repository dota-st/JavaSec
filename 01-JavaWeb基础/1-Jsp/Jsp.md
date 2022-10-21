# Jsp基础

## 概念

JSP 与 PHP、ASP 等脚本语言类似，早期为了简化`Servlet`的处理流程而诞生，目的是起到快速处理后端的逻辑请求任务。因为 Jsp 可以直接调用 Java 代码的特性，成为了 Webshell 的载体。

## 指令

- `<%@ page ... %>`：定义网页依赖属性，比如脚本语言，error 页面等。
- `<%@ include ...%>`：包含其他文件（静态）
- `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>`：引入标签库的定义

## JSP表达式（EL）

EL表达式( Expression Language )语言,常用于在jsp页面中获取请求中的值，使用EL表达式可以实现命令执行，这里只是简单说一下概念，具体实现等到用时再聊，这里不展开。

- 立即求值：`${}`
- 延迟求值：`#{}`

## JSP标准标签库（JSTL）

JSP标准标签库（JSTL）是一个JSP标签集合，它封装了JSP应用的通用核心功能。

JSTL支持通用的、结构化的任务，比如迭代，条件判断，XML文档操作，国际化标签，SQL标签。 除了这些，它还提供了一个框架来使用集成JSTL的自定义标签。

## JSP对象

从本质上说 JSP 就是一个Servlet，JSP 引擎在调用 JSP 对应的 jspServlet 时，会传递或创建 9 个与 web 开发相关的对象供 jspServlet 使用。 JSP 技术的设计者为便于开发人员在编写 JSP 页面时获得这些 web 对象的引用，特意定义了 9 个相应的变量，开发人员在JSP页面中通过这些变量就可以快速获得这 9 大对象的引用。

如下：

| 变量名      | 类型                | 作用                                        |
| ----------- | ------------------- | ------------------------------------------- |
| pageContext | PageContext         | 当前页面共享数据，还可以获取其他8个内置对象 |
| request     | HttpServletRequest  | 客户端请求对象，包含了所有客户端请求信息    |
| session     | HttpSession         | 请求会话                                    |
| application | ServletContext      | 全局对象，所有用户间共享数据                |
| response    | HttpServletResponse | 响应对象，主要用于服务器端设置响应信息      |
| page        | Object              | 当前Servlet对象,`this`                      |
| out         | JspWriter           | 输出对象，数据输出到页面上                  |
| config      | ServletConfig       | Servlet的配置对象                           |
| exception   | Throwable           | 异常对象                                    |
