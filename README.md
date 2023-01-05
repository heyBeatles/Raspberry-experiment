

对于实验复现如有问题，可通过邮箱联系作者：bincanlin@qq.com

The English version of the running instructions is located under the Chinese version, please turn to see it. If you have any questions, please contact the author at bincanlin@qq.com

### 树莓派硬件实验运行说明

硬件实验encrypted_kWTA项目使用C++开发，基于树莓派的linux系统raspberry os : buster开发

#### 1.运行软硬件要求

硬件要求：

树莓派3b四台、TF卡四张、LED小灯四个、电阻四个、面包板一张、导线若干

软件要求：

①raspberry操作系统版本：raspios-buster-arm64

下载地址：http://downloads.raspberrypi.org/raspios_arm64/images/raspios_arm64-2020-05-28/2020-05-27-raspios-buster-arm64.zip

②大整数运算库：[GNU Multiple Precision Arithmetic Library](http://gmplib.org/) (GMP) 

安装教程：https://stackoverflow.com/questions/65648379/how-to-install-gnu-mp-gmp-in-codeblocks-on-linux-mint

③paillier加密算法运算库：[libpaillier-0.8.tar.gz]

下载地址：http://acsc.cs.utexas.edu/libpaillier/libpaillier-0.8.tar.gz

④64位wiringPi树莓派GPIO控制库

下载地址：https://github.com/guation/WiringPi-arm64

#### 2.运行说明

在代码文件client.cpp的initNeighbor方法中中设置四个树莓派节点的ip地址和初始输入input，设置完成之后在每个树莓派上编译并运行项目即可

项目为cmake工程，在项目目录下逐个执行一下步骤

①加载cmake工程

cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" -S . -B ./cmake-build-debug

②编译项目

cmake --build ./cmake-build-debug/ --target client -- -j 12

③运行可执行程序，执行命令后面的运行参数4和0分别代表网络中总共有4个节点，当前运行节点为为0号节点（4个节点的编号分别为0、1、2、3），运行后cmake-build-debug目录下得到一个名称为clientXXX.txt的文件，为运行过程的变量状态记录

./cmake-build-debug/client 4 0

随着运行次数增多，各个状态达到最终收敛之后，能够看到控制台打印的z变量变为1或0,0表示当前节点不是前k个最大值，1表示当前节点为前k个最大值，输出为1的节点会亮起LED小灯







### Raspberry Pi hardware experimental run description

Hardware experiments encrypted_kWTA project developed in C++, based on the Raspberry Pi linux system raspberry os : buster for development

#### 1.Running hardware and software requirements

Hardware requirements:

Raspberry Pi 3b four, TF card four, four small LED lights, four resistors, a breadboard, a number of wires

Software requirements:

①raspberry operating system version：raspios-buster-arm64

Download Address：http://downloads.raspberrypi.org/raspios_arm64/images/raspios_arm64-2020-05-28/2020-05-27-raspios-buster-arm64.zip

②Large integer library：[GNU Multiple Precision Arithmetic Library](http://gmplib.org/) (GMP) 

Installation Tutorial：https://stackoverflow.com/questions/65648379/how-to-install-gnu-mp-gmp-in-codeblocks-on-linux-mint

③paillier cryptographic algorithm library：[libpaillier-0.8.tar.gz]

Download Address：http://acsc.cs.utexas.edu/libpaillier/libpaillier-0.8.tar.gz

④64-bit wiringPi Raspberry Pi GPIO control library

Download Address：https://github.com/guation/WiringPi-arm64

#### 2.Running instructions

In the initNeighbor method of the code file client.cpp, set the ip addresses and initial input inputs of the four Raspberry Pi nodes, and compile and run the project on each Raspberry Pi after the settings are completed

The project is a cmake project, execute the following steps one by one in the project directory

①Load the cmake project

```
cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" -S . -B . /cmake-build-debug
```

② Build the project

```
cmake --build . /cmake-build-debug/ --target client -- -j 12
```

③Run the executable program, execute the command followed by the run parameter 4 and 0 represent a total of 4 nodes in the network, the current running node is node 0 (the number of the four nodes are 0, 1, 2, 3), after running cmake-build-debug directory to get a file named clientXXX.txt, for the running process of variable status records

```
. /cmake-build-debug/client 4 0
```

As the number of runs increases, each state reaches the final convergence, you can see the z variable printed on the console becomes 1 or 0, 0 means the current node is not the first k maximum, 1 means the current node is the first k maximum, the output of 1 node will light up LED lights
