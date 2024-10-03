
<div align="center">

![Network Communications Lab Logo](UniversityLogo.jpeg)

# NetlabTAU Project

</div>

This project is part of the **Advanced Computer Communications Lab** at **Tel-Aviv University**. It aims to enhance the lab infrastructure by refining the current implementation and integrating new protocols across various system layers.

## Table of Contents
- [Installation](#installation)
- [Project Configuration](#project-configuration)
- [Debug Tools](#debug-tools)
- [Tests](#tests)
- [Contributors](#contributors)
- [License](#license)

## Installation
To get started with the NetlabTAU project, follow these installation instructions:

1. Install **Microsoft Visual Studio 2022**.
2. Clone the [NetlabTAU repository](https://github.com/GabrielKlyatis/NetlabTAU).
3. Download and install the following dependencies:
   - [Boost](https://www.boost.org/users/download/)
   - [pthreads-win32](https://sourceware.org/pthreads-win32/)
   - [WinPcap Developer’s Pack](https://www.winpcap.org/devel.htm)
   - [OpenSSL (version 3.0+)](https://slproweb.com/products/Win32OpenSSL.html)
   - [GoogleTest framework](https://github.com/google/googletest)

For detailed instructions on setting up these dependencies, refer to the `Setup` section in the [manual](./NetlabTAU_Manual.pdf).

## Project Configuration

Once the required dependencies are installed, follow these steps to configure the project:

1. Right-click the **Sniffer** project in Visual Studio and choose **Properties**.
   - Edit the **Include Directories** section in **VC++ Directories** to include paths to dependencies.
   - Set **Configuration Type** to static library (`.lib`).
2. Right-click the **NetlabTAU** project and configure it based on your system setup as either a static library or executable.
   - Include directories for dependencies such as WpdPack, pthread, Boost, OpenSSL, and GoogleTest.
3. Link the required libraries (e.g., `wpcap.lib`, `pthreadVC2.lib`, `libssl.lib`).

Refer to the full setup guide in the [manual](./NetlabTAU_Manual.pdf) for additional details.

## Debug Tools

The following debugging tools are recommended for this project:
- **Visual Studio Debugger** – Integrated debugging tool within Visual Studio.
- **Wireshark** – A network protocol analyzer to capture and analyze real-time traffic.
- **Postman** – An API testing tool for inspecting HTTP traffic.

Download links and further instructions can be found in the [manual](./NetlabTAU_Manual.pdf).

## Tests

We use **GoogleTest (GTest)** to implement unit tests for this project. The test suite is modular and easily maintainable.

To run the tests:
- Install GoogleTest and ensure it is linked to the project.
- Build and run tests through Visual Studio or command line:
  ```bash
  ./netlab_testing --gtest_filter=TestSuite.TestName
  ```

For more details on adding new tests or test fixtures, refer to the [manual](./NetlabTAU_Manual.pdf).

## Contributors

- **Gabriel Klyatis**
- **Niv Shani**
- **Supervisors**: Prof. Boaz Patt-Shamir, Dr. Tom Mahler

## License
This project is licensed under the Tel-Aviv University licensing terms. Refer to the LICENSE file for more information.
