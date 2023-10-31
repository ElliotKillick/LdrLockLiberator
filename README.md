<div align="center">
    <a href="https://github.com/ElliotKillick/LdrLockLiberator">
        <img width="160" src="logo.webp" alt="Logo" />
    </a>
</div>

<h2 align="center">
    LdrLockLiberator
</h2>

<p align="center">
    For when <b>DLLMain</b> is the only way
</p>

LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from `DllMain` or anywhere else the lock may be present. It was released in conjuction with the ["Perfect DLL Hijacking"](https://elliotonsecurity.com/perfect-dll-hijacking) article. We give you the <b>key</b> to unlock the library loader and do what you want with your loader (on your own computer)!

The techniques are intended to be **universal, clean, and 100% safe** where possible. They're designed to work without modifying memory protection or pointers. This is important for staying compatible with modern exploit mitigations.

## Techniques

### LdrFullUnlock

It's exactly what it sounds like. Unlock Loader Lock, set loader events, and flip `LdrpWorkInProgress`. It's recommended to keep `RUN_PAYLOAD_DIRECTLY_FROM_DLLMAIN` undefined for the best stability.

**DO NOT USE THIS TECHNIQUE IN PROUDCTION CODE.** This was created as a byproduct of my shear curiosity and will to leave no stone unturned. Anything you do with this code is on you.

### Escaping at the Exit

We use the CRT `atexit` typically used by EXEs in our DLL code to escape Loader Lock when the program exits. For dynamic loads, this is made <b>100% safe</b> by pinning (`LDR_ADDREF_DLL_PIN`) our library using `LdrAddRefDll` so a following `FreeLibrary` won't remove our DLL from memory.

### Using Locks to Our Advantage

Coming soon!

## Samples

The provided samples hijack `MpClient.dll` from `C:\Program Files\Windows Defender\Offline\OfflineScannerShell.exe`. Instructions are provided in the source code comments to easily adapt this for any other DLL and program pairing (primarily just updating the exports for static loads)!

As a proof of concept, we run `ShellExecute` as the default payload. You can make this anything you want!

## Compilation

### Visual Studio

The `LdrLockLiberator.c` at the root of this project has been tested to compile on Visual Studio 2022.

### WDK

#### Installing the Correct WDK

1. Go to the [WDK download page](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads#step-2-install-the-wdk)
2. Click on the Windows 7 [WDK 7.1.0](https://www.microsoft.com/en-us/download/confirmation.aspx?id=11800) link to start download the correct WDK version
  - This is the last WDK that **officially** supports linking to the original MSVCRT (`C:\Windows\System32\msvcrt.dll`)
  - SHA-256 sum: `5edc723b50ea28a070cad361dd0927df402b7a861a036bbcf11d27ebba77657d`
3. Mount the downloaded ISO then run `KitSetup.exe`
4. Click through the installation process using the default options

#### Compiling

1. In the Start menu, search for "x64 Free Build Environment" then open it
2. Navigate (using `cd`) to `LdrLockLiberatorWDK` in this repo
3. Run `build`

Done! Your DLL is built and ready for use!

As an alternative to WDK, cross-compiling with MinGW would also probably work.

## License

MIT License - Copyright (C) 2023 Elliot Killick <contact@elliotkillick.com>
