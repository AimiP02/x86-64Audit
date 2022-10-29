# x86-64Audit

## Backgound

参考giantbranch的mipsAudit的项目编写的IDAPro7.7 x86-64Audit

具体功能有：
- 查找危险函数调用地址，高亮地址行
- 添加注释
- 以表格形式输出函数名、调用地址、参数、缓冲区大小

## Usage

![](https://bronya-1256118329.cos.ap-shanghai.myqcloud.com/img/202210291319532.png)

菜单栏点击文件 -> 脚本文件，选择`x86-64Audit.py`，输出在Output栏中

    prettytable.py -> 规范化表格
    functable.py   -> 检索函数表
    x86-64Audit.py -> 审计脚本

## Example

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buf[100];
    char buf2[50];
    char buf3[50];
    read(0, buf, 100);
    read(0, buf, 50);
    strcpy(buf3, buf2);
    printf("Hello, %s, %s", buf, buf2);
    printf("Bye %s", buf2);
    return 0;
}
```

使用`gcc test.c -o test`编译文件

![](https://bronya-1256118329.cos.ap-shanghai.myqcloud.com/img/202210291331707.png)