# Filter基础

## 概念

`javax.servlet.Filter`是`Servlet2.3`新增的一个特性,主要用于过滤URL请求，通过Filter我们可以实现URL请求资源权限验证、用户登陆检测等功能。

Filter是一个接口，实现一个Filter只需要重写`init`、`doFilter`、`destroy`方法即可，其中过滤逻辑都在`doFilter`方法中实现。

`Filter`的配置类似于`Servlet`，由`<filter>`和`<filter-mapping>`两组标签组成，如果Servlet版本大于3.0同样可以使用注解的方式配置Filter。

## 基于注解实现的Filter

简单写个 demo

```
package com.servlet.study;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import java.io.IOException;

/**
 * Created by dotast on 2022/10/21 10:41
 */
@WebFilter(filterName = "ServletTest", urlPatterns = {"/*"})
public class ServletTest implements Filter {

    public void init(FilterConfig filterConfig) throws ServletException {

    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String name = servletRequest.getParameter("name");
        if(name.equals("admin")){
            // 跳转到 amdin.jsp
            RequestDispatcher redirect = servletRequest.getRequestDispatcher("/admin.jsp");
            redirect.forward(servletRequest,servletResponse);
        }else {
            RequestDispatcher redirect = servletRequest.getRequestDispatcher("/loginerror.jsp");
            redirect.forward(servletRequest,servletResponse);
        }
        // 使下一个 Filter 能够继续执行
        filterChain.doFilter(servletRequest,servletResponse);
    }

    public void destroy() {

    }
}
```

![image-20221021163302120](images/image-20221021163302120.png)
