
<div align="center">

![Network Communications Lab Logo](UniversityLogo.jpeg)

# NetlabTAU Project

</div>

# NetlabTAU Project

This project is part of the **Advanced Computer Communications Lab** at **Tel-Aviv University**. It aims to improve the infrastructure of network protocol testing by refining the current implementation and integrating new protocols across various system layers. The following document provides a detailed guide on how to install, configure, test, and debug the project.

## Table of Contents

- [Setup](#setup)
  - [Installation](#installation)
  - [Project Configuration](#project-configuration)
  - [Debug Tools](#debug-tools)
- [Tests](#tests)
  - [General](#general)
  - [Setting Up GoogleTest](#setting-up-googletest)
  - [Testing Approach](#testing-approach)
  - [How to Use](#how-to-use)
  - [How to Add Tests](#how-to-add-tests)
  - [Implemented Tests Overview](#implemented-tests-overview)
  - [How to Check the Implementation of Students](#how-to-check-the-implementation-of-students)
- [Notes](#notes)
  - [TLS Debugging](#tls-debugging)
  - [L0 Buffer](#l0-buffer)
  - [HTTP](#http)

---

## Setup

### Installation

1. Install **Microsoft Visual Studio 2022**.
2. Clone the [NetlabTAU](https://github.com/GabrielKlyatis/NetlabTAU) project repository onto your machine.
3. Download and install the latest versions of the following:
   - [Boost](https://www.boost.org/users/download/) version 1.83.
   - [pthreads-win32](https://sourceware.org/pthreads-win32/).
   - [WinPcap Developer’s Pack](https://www.winpcap.org/devel.htm) version 4.1.2.
   - [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) version 3.0+ (Win32/Win64 based on your system).
   - [GoogleTest framework](https://github.com/google/googletest).

### Project Configuration

1. Under "Solution Explorer", right-click the **Sniffer** project and choose **Properties**:
   - Go to **VC++ Directories** and edit the **Include Directories** section.
     ![Sniffer Dependencies](./manual_prints/Setup/sniffer_config.PNG)
   - Insert the paths for the installed dependencies (WpdPack, Boost, pthread, OpenSSL, and GoogleTest).
   - Set the **Configuration Type** to static library (`.lib`).
     ![Sniffer Configuration Type](./manual_prints/Setup/sniffer_compiling.PNG)
   
2. Right-click the **NetlabTAU** project in "Solution Explorer" and choose **Properties**:
   - Edit the **Include Directories** section for WpdPack, pthread, Boost, OpenSSL, and GoogleTest.
     ![netlab Dependencies](./manual_prints/Setup/netlab_vcc+.PNG)
     - The exact paths in our configuration for each of the libraries:
        ```
        - C:\googletest1.14.0\googletest\include
        - C:\Projects\pthreads-w32-2-9-release\Pre-built.2\include
        - C:\Projects\WpdPack 4 1 2\WpdPack\Include
        - C:\Projects\boost 1 83 0
        - C:\Projects\OpenSSL-Win32\include
        ```
   - If NetlabTAU is an executable project, go to **Linker > Input** and add the paths for the required libraries (e.g., `wpcap.lib`, `pthreadVC2.lib`, etc.).
       ```
        – wpcap.lib
        – pthreadVC2.lib
        – Iphlpapi.lib
        – ws2 32.lib
        – libssl.lib
        – libcrypto.lib
       ```
    ![netlab Linker](./manual_prints/Setup/netlab_exe_linker.PNG)

  - The exact paths in our configuration for each of the files:
       ```
        - Debug\Sniffer.lib
        - C:\Projects\WpdPack 4 1 2\WpdPack\Lib\wpcap.lib
        - C:\Projects\pthreads-w32-2-9-1-release\Pre-built.2\lib\x86\pthreadVC2.lib
        - Iphlpapi.lib
        - ws2 32.lib
        - C:\Projects\OpenSSL-Win32\lib\VC\x86\MDd\libssl.lib
        - C:\Projects\OpenSSL-Win32\lib\VC\x86\MDd\libcrypto.lib
       ```

4. Finally, under ”Solution Explorer”, right-click the **netlab testing** project and choose ”Properties”.
Go to ”VC++ Directories” and edit the ”Include Directories” section - Insert the paths for the previously installed dependencies of WpdPack, pthread, Boost, OpenSSL and GoogleTest.

  ![netlab testing Dependencies](./manual_prints/Setup/netlab_testing_vcc.PNG)

  - The exact paths in our configuration for each of the libraries:
      ```
      - C:\googletest1.14.0\googletest\include
      - C:\Projects\pthreads-w32-2-9-release\Pre-built.2\include
      - C:\Projects\WpdPack 4 1 2\WpdPack\Include
      - C:\Projects\boost 1 83 0
      - C:\Projects\OpenSSL-Win32\include
      ```
5. Go to ”Linker”, ”Input” and edit the ”Additional Dependencies” section - Insert the paths for:

  ```
      – Sniffer.lib
      – NetlabTAU.lib
      – wpcap.lib
      – pthreadVC2.lib
      – Iphlpapi.lib
      – ws2 32.lib
      – libssl.lib
      – libcrypto.lib
  ```
  
  ![netlab testing Linker](./manual_prints/Setup/netlab_testing_linker.PNG)

  - The exact paths in our configuration for each of the files:
      ```
      - ..\netlab\Debug\Sniffer.lib
      - ..\netlab\Debug\NetlabTAU.lib
      - C:\Projects\WpdPack 4 1 2\WpdPack\Lib\wpcap.lib
      - C:\Projects\pthreads-w32-2-9-1-release\Pre-built.2\lib\x86\pthreadVC2.lib
      - Iphlpapi.lib
      - ws2 32.lib
      - C:\Projects\OpenSSL-Win32\lib\VC\x86\MDd\libssl.lib
      - C:\Projects\OpenSSL-Win32\lib\VC\x86\MDd\libcrypto.lib
      ```
  
### Debug Tools

Debugging tools are essential for identifying and resolving issues in software development. The following
Tools are a must to understand and handle the project:

- **Visual Studio’s Debugger**: A powerful integrated tool that allows you to set breakpoints, inspect
variables, and step through code execution. It simplifies debugging C++ projects by providing a
clear view of the program’s state during runtime. Comes with the IDE ([Beginner's Tutorial](https://learn.microsoft.com/en-us/visualstudio/debugger/debugger-feature-tour?view=vs-2022)).

- **Wireshark version 4.2.2**: A widely used network protocol analyzer that captures and displays
real-time data traffic. This is invaluable for debugging networking protocols and verifying commu-
nication flows within the project. You can get it [here](https://www.wireshark.org/download.html).

- **Postman**: A widely used API testing tool that allows users to send HTTP requests and
analyze responses. It helps developers inspect HTTP traffic by providing detailed views of requests,
responses, headers, and status codes. This makes it ideal for testing and debugging APIs, as well
as monitoring client-server interactions. You can get it [here](https://www.postman.com/downloads/).

---

## Tests

### General

The testing framework for this project has been developed in a separate repository named netlab-testing,
ensuring that all testing efforts are modular and easily maintainable. At the core of our testing strategy
is GoogleTest (GTest), a robust and widely adopted framework for writing C++ tests. GTest not only
simplifies the process of writing unit tests but also integrates seamlessly with modern development tools,
enabling automated test execution and result analysis. By leveraging this powerful framework, we ensure
that our code remains reliable, maintainable, and easy to refactor as the project evolves.

More on the GoogleTest framework can be found in the [official documentation](https://google.github.io/googletest/)

### Setting Up GoogleTest

1. Download and install [GoogleTest](https://github.com/google/googletest).
2. Setup [GoogleTest in Visual Studio](https://learn.microsoft.com/en-us/visualstudio/test/how-to-use-google-test-for-cpp?view=vs-2022).
3. Setup netlab testing’s project environment, as described above.

### Testing Approach

In our testing approach using Google Test (GTest), each test is encapsulated within a test fixture object,
which follows a structured interface: ```setUp()``` and ```tearDown()```. For consistency and modularity, we have
designed every protocol test as a test fixture. The flow of each test is broken down into four key stages:

- **Constructor**: Initializes the test components (such as the TCP/IP stack layers and network inter-
face controllers). This is executed only once per test.
- **setUp()**: Configures two inet os instances (client and server), spawns packet sniffers, and initializes
the network domain.
- **Test Execution**: Sends and receives data, performing comparative tests between regular OS sockets
and inet os sockets.
- **tearDown()**: Terminates the sniffers and ensures the connection closes cleanly.
  
### How to Use

1. Ensure that you have GoogleTest installed and properly linked to your project.
2. Compile the tests - to compile tests with GoogleTest, make sure the appropriate include directories and libraries are
linked (e.g., via Visual Studio). Then, proceed to build your project.
3. Run the tests using either Visual Studio or the Command Line
  To run all tests:
     ```
     ./netlab_testing
     ```
  If you want to run a specific test, use the ```--gtest``` filter flag. The syntax is: ```TestSuite.TestName```.
  You can also use the wildcard * to run all tests under a specific test suite, for example:
     ```
     ./netlab_testing --gtest_filter=tcpTest.sender_test
     ```
Or to run all tests under the TCP Tests suite:
  ```
  ./netlab_testing --gtest_filter=TCP_Tests.*
  ```

Other Useful flags:

```
--gtest repeat=[COUNT]
```
Runs the test suite multiple times. 
```
--gtest shuffle
``` 
Runs the tests in a random order.
  
For example, the following command runs all TCP Tests tests 100 times in random order:
```
./netlab_testing --gtest_filter=tcpTest.* --gtest_repeat=100 --gtest_shuffle
```

## Using Visual Studio

To run tests within Visual Studio:

1. Open Visual Studio and choose ”Open a project or solution”:
   ![VS Open Solution/Project](./manual_prints/Testing/open_proj.PNG)
2. Navigate to your project directory and choose the .sln or .proj file:
   ![VS .sln .proj](./manual_prints/Testing/files.PNG)
3. Ensure that your tests are built correctly. Go to Test → Run All Tests or use the Test Explorer window to select and run individual tests:
   ![VS run all tests](./manual_prints/Testing/runtests.PNG)
4. It's also possible to debug specific tests by right-clicking on them in the Test Explorer and selecting Debug Selected Tests:
   ![VS run specific test](./manual_prints/Testing/select_test.PNG)
5. Test results will be displayed in the Test Explorer, where you can view the pass/fail status for each test, along with any additional related output.
   ![VS test to run](./manual_prints/Testing/testtorun.PNG)

## Contributors

- **Gabriel Klyatis**
- **Niv Shani**
- **Supervisors**: Prof. Boaz Patt-Shamir, Dr. Tom Mahler

## License
This project is licensed under the Tel-Aviv University licensing terms. Refer to the LICENSE file for more information.
