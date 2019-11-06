# Android Emulator Hypervisor Driver for AMD Processors
Android Emulator Hypervisor Driver for AMD Processors is a hypervisor to
accelerate [Android Emulator][android-studio]. It is made by porting KVM to
Windows (Windows 7 or later, 64bit).

Android Emulator Hypervisor Driver for AMD Processors runs as a Windows driver.
User space support for Android Emulator Hypervisor Driver for AMD Processors is
available from Android Emulator.

## Downloads
Android Emulator Hypervisor Driver for AMD Processors is released through
[android-studio].

## Contributing
If you would like to contribute a patch to the code base, please read
[these guidelines](CONTRIBUTING.md).

## Reporting an Issue
You are welcome to file an issue at [Issuetracker]. Please remember to supply
your OS information, CPU model in addition to details on the issue.

## Notes
At the time of open source releasing, user space support from [qemu] is NOT
offered. But it should be straight forward if you need to port from Android
Emulator to qemu.

As its name suggests, Android Emulator Hypervisor Driver for AMD Processors is
developed and tested on AMD platform. We only make our best effort in keeping
Intel Processor support.

[android-studio]: https://developer.android.com/studio/index.html
[qemu]: https://www.qemu.org/
[Issuetracker]: https://issuetracker.google.com/issues?q=componentid:192727
