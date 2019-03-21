# PyOne主题开发规范

PyOne是基于Flask开发的，前端使用jinja2模板语言，对于不熟悉的开发者来说，主题开发起来比较麻烦，这里做一个简单解析。

欢迎前端大佬做出优秀主题，然后pr到PyOne下来。



**主题放在哪里？**

主题目录统一放在`PyOne/templates/theme/`下

**必须有哪些页面？**

以自带主题为例
```
theme
    └── material
        ├── 500.html -- 500错误页面，必须有这个页面
        ├── find.html -- 搜索结果页面，必须要有这个页面
        ├── footer.html
        ├── header.html
        ├── head.html
        ├── index.html  -- 主页页面，必须有这个页面。
        ├── layout.html
        ├── _macro.html
        ├── password.html -- 输入密码页面，必须要有这个页面
        ├── readme.html
        └── show -- 这个文件夹下的页面都是必须要有的。
            ├── any.html
            ├── audio.html
            ├── code.html
            ├── image.html
            ├── video2.html
            └── video.htm
```

**设计规范转移到wiki：[https://wiki.pyone.me](https://wiki.pyone.me)**
