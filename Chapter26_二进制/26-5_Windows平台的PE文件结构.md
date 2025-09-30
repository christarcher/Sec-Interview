### 讲讲 Windows 平台的 PE 文件结构

**PE 文件的双重性质**

PE 文件的结构可以看作是**DOS 文件**和 **PE 文件**的结合体。这种设计是为了保持与旧版 DOS 操作系统的兼容性。当你双击一个 PE 文件时，操作系统首先会将其作为一个 DOS 程序处理

PE 文件主要由以下几个核心部分组成：

1. **DOS 头部 (DOS Header)**
2. **DOS Stub (DOS 存根)**
3. **NT 头部 (NT Header)**
4. **可选头部 (Optional Header)**
5. **节表 (Section Table)**
6. **节 (Sections)**

**1. DOS 头部 (DOS Header)**

这是 PE 文件的最前端，一个 `IMAGE_DOS_HEADER` 结构体

- **`e_magic`**：4 字节的魔数，固定为 `0x4D5A` (ASCII 字符 **"MZ"**)。这是识别 PE 文件的标志
- **`e_lfanew`**：一个关键的字段，它是一个 4 字节的偏移量，指向 **NT 头部**的起始位置

**2. DOS Stub (DOS 存根)**

这是一个小型的 DOS 程序。当在 DOS 环境下执行这个文件时，它会打印一句经典的提示语：“This program cannot be run in DOS mode.”。它的唯一作用就是为了兼容性

**3. NT 头部 (NT Header)**

NT 头部是 PE 文件的真正核心，它是一个 `IMAGE_NT_HEADERS` 结构体，由三个部分组成：

- **`Signature`**：4 字节的签名，固定为 `0x50450000` (ASCII 字符 **"PE\0\0"**)。这标志着它是一个有效的 PE 文件
- **`FileHeader` (文件头部)**：一个 `IMAGE_FILE_HEADER` 结构体，包含了文件的基本属性，比如：
  - **`Machine`**：指定文件适用的 CPU 架构，如 `0x14C` (Intel 386)
  - **`NumberOfSections`**：文件中包含的节的数量
  - **`SizeOfOptionalHeader`**：可选头部的大小
  - **`Characteristics`**：文件的特性，如是否是可执行文件、是否是 DLL 等
- **`OptionalHeader` (可选头部)**：一个 `IMAGE_OPTIONAL_HEADER` 结构体，这部分虽然叫“可选”，但对于可执行文件来说是必需的。它包含了加载器需要的大部分信息，是理解 PE 结构的关键

**4. 可选头部 (Optional Header)**

可选头部包含了 PE 文件的加载信息，例如：

- **`Magic`**：标志着文件是 32 位 (`0x10B`) 还是 64 位 (`0x20B`)
- **`AddressOfEntryPoint`**：程序的入口点地址，它是一个 **RVA (Relative Virtual Address)**。当文件加载后，加载器会将控制权交给这个地址
- **`ImageBase`**：程序加载到内存中的首选基址
- **`SectionAlignment`** 和 **`FileAlignment`**：内存中和文件中的节对齐粒度
- **`SizeOfImage`**：整个文件被加载到内存后占用的总大小
- **`DataDirectory` (数据目录)**：这是最重要的部分之一，一个 `IMAGE_DATA_DIRECTORY` 结构体数组。它包含了 PE 文件中各种重要数据结构的位置和大小，例如：
  - **`Import Table` (导入表)**：记录了程序依赖的 DLL 和从中导入的函数。加载器在运行时会根据这个表填充函数的真实地址
  - **`Export Table` (导出表)**：记录了 DLL 文件中供其他程序调用的函数
  - **`Resource Table` (资源表)**：包含了图标、光标、菜单、对话框等资源数据
  - **`Base Relocation Table` (基址重定位表)**：当文件无法加载到其首选基址时，需要进行重定位，这个表记录了所有需要修正的地址
  - **`TLS Table` (线程本地存储表)**：记录了线程相关的数据
  - **`Debug Directory` (调试目录)**：指向调试信息

**5. 节表 (Section Table)**

紧跟在可选头部后面的是节表。这是一个 `IMAGE_SECTION_HEADER` 结构体数组，数组中的每个结构体都描述了一个**节**

- **`Name`**：节的名称，如 `.text`, `.data`, `.rdata` 等
- **`VirtualAddress`**：该节在内存中的 RVA
- **`SizeOfRawData`**：该节在文件中的大小
- **`PointerToRawData`**：该节在文件中的偏移量
- **`Characteristics`**：节的属性，例如**可读、可写、可执行**等权限

**6. 节 (Sections)**

节是 PE 文件中包含实际数据和代码的区域。它们是根据功能和权限来划分的。常见的节有：

- **`.text`**：包含可执行代码和只读数据。在内存中通常具有**只读和可执行**权限
- **`.data`**：包含已初始化的全局变量和静态变量。在内存中通常具有**可读和可写**权限
- **`.rdata`**：包含只读数据，如字符串常量、导入表、导出表等。在内存中通常具有**只读**权限
- **`.idata`**：导入表
- **`.edata`**：导出表
- **`.rsrc`**：资源数据，如图标和位图
- **`.reloc`**：基址重定位表

**PE 文件加载过程**

当 Windows 加载器加载一个 PE 文件时，它会：

1. **检查 DOS 头部和 NT 头部**，确认文件是有效的 PE 格式
2. **根据可选头部中的 `ImageBase` 和 `SizeOfImage`** 为程序在内存中分配虚拟地址空间
3. **遍历节表**，将文件中的各个节根据其在文件中的偏移和在内存中的 RVA，映射到先前分配的内存空间中
4. **处理导入表**，将程序依赖的 DLL 加载到内存，并填充导入表中的函数地址
5. **如果文件无法加载到其首选基址**，加载器会处理基址重定位表，修正所有需要调整的地址
6. **将控制权转移到入口点** (`AddressOfEntryPoint`)，程序开始执行