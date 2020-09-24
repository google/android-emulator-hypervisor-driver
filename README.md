# Android Emulator Hypervisor Driver for AMD Processors
Android Emulator Hypervisor Driver for AMD Processors is a hypervisor to
accelerate [Android Emulator][android-studio]. It is made by porting KVM to
Windows (Windows 7 or later, 64bit).

Android Emulator Hypervisor Driver for AMD Processors runs as a Windows driver.
User space support for Android Emulator Hypervisor Driver for AMD Processors is
available from Android Emulator.

## Download and Install
Android Emulator Hypervisor Driver for AMD Processors is released through
[android-studio]. However, only Android Studio with version 4.0 canary 5 or
above can both download and install/update the driver. Otherwise, the Android
Studio will only download the driver package without performing installation.
In the latter case, users are required to install the driver manually.


Prerequisite:
1. CPU has virtualization extension and BIOS has NOT disabled the extension.
2. Hyper-V must be disabled. Refer to [this
   page](https://github.com/google/android-emulator-hypervisor-driver-for-amd-processors/wiki/Is-Hyper-V-really-disabled%3F)
   for more information.

Install Instruction:  
  
Use an administrator command console to execute "silent_install.bat" inside
the driver package. Make sure you see the desired output from the installer:
STATE: 4 RUNNING

## Contributing
If you would like to contribute a patch to the code base, please read
[these guidelines](CONTRIBUTING.md).

## Reporting an Issue
You are welcome to file an issue at [Issuetracker]. Please remember to supply
your OS information, CPU model in addition to details on the issue.

## Notes
A patched QEMU can be found here at [github]. However, there is no support for
it. Use at your own risk.

As its name suggests, Android Emulator Hypervisor Driver for AMD Processors is
developed and tested on AMD platform. We only make our best effort in keeping
Intel Processor support.

[android-studio]: https://developer.android.com/studio/index.html
[github]: https://github.com/qemu-gvm/qemu-gvm
[Issuetracker]: https://issuetracker.google.com/issues?q=componentid:192727
