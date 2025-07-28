# winhorse
A minimalistic Windows compatibility layer for KUBERA

## Work-In-Progress

This project includes example usage of [KUBERA](https://github.com/binsnake/KUBERA) for emulating Windows applications. 

It is implemented as a system emulation layer.

## Building

Clone the repository recursively.

`mkdir build`

`cd build`

`cmake .. && cmake --build .`

## Dependencies

A C++ compiler supporting C++23 or higher.

A Rust compiler for [Iced](https://github.com/binsnake/icedpp)

## Third-party dependencies

[Can1357's Linux-PE](https://github.com/can1357/linux-pe) - For cross-platform parsing of Windows Portable-Executable Format.

[Boost::MultiPrecision Library](https://github.com/boostorg/multiprecision) - For large integer and multi-precision floating point arithmetic.

## References

[momo5502's sogen](https://github.com/momo5502/sogen) - A x86_64 Windows Userspace emulator
