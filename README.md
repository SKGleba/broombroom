# broombroom
Playstation Vita first_loader hack for prototype units on firmware 1.03
<br>This hack grants "bootrom"-level code execution on the PSP2 by exploiting a [first_loader vulnerability](https://wiki.henkaku.xyz/vita/Vulnerabilities#First_Loader_SLSK_buffer_overflow) discovered by Team Molecule
## Usage
- You will need [mepsdk](https://github.com/TeamMolecule/mepsdk) and [vitasdk](https://vitasdk.org/)
- Compile all the cmep-payloads, make sure that resulting byte arrays are *static const*
- Compile the main code, the result should be *kexec.bin*
- Run *kexec.bin* in THUMB mode with a kernel exploit such as [this one](https://github.com/mathieulh/PS-Vita-Early-Kernel-Exploit-Toolbox)
## Notes
- By default, broombroom expects arg to be a user-space pointer to a decrypted 3.65 second_loader.enc
  - it is only used for convenience, it is not required for the hack itself
- Porting to a firmware different than 1.03 requires offset changes in the kernel and tz payloads
## Credits
- 'Proxima' for [*help and guidance*](https://dictionary.cambridge.org/dictionary/english/spoon-feed) over discord
- 'Team Molecule' for the user, kernel, bootloader, trustzone, update_sm and bootrom exploits as well as mepsdk and [sceutils](https://github.com/TeamMolecule/sceutils)
- 'Zecoxao', 'LemonHaze', 'Princess Of Sleeping'
- All [henkaku wiki](https://wiki.henkaku.xyz/) and vitasdk contributors
- 'Yasen' for providing a type B prototype devkit and lots of electrons.
