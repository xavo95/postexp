# Introduction

Give me tfp0, I give you jelbrek
This is a helper library to be used in jailbreak development or post explotation.
Call this a (light?) QiLin open-source alternative.

# Compiling:

    ./make.sh
    
# Setup

- Compile OR head over to https://github.com/jakeajames/jelbrekLib/tree/master/downloads and get everything there. 
- Link with postexp.a & IOKit.tbd and include postexp.h
- Call init() with tfp0 as your first thing and term_jelbrek() as your last

# Issues
- AMFID patch won't resist after app enters background. Fix would be using a daemon (like amfidebilitate) or injecting a dylib (iOS 11)

# iOS 12 satus
- rootFS remount is broken. There is hardening on snapshot_rename() which *can* and *has* been (privately) bypassed, but it for sure isn't as bad as last year with iOS 11.3.1, where they made **major** changes. The only thing we need is figuring out how they check if the snapshot is the rootfs and not something in /var for example where snapshot_rename works fine.
- kexecute() is also probably broken on A12. Use bazad's PAC bypass which offers the same thing, so this isn't an issue (fr now)
- getting root, unsandboxing, NVRAM lock/unlock, setHSP4(), trustbin(), entitlePid + task_for_pid() are all working fine. The rest that is not on top of my mind should also work fine.

## Codesign bypass
- Patching amfid should be a matter of getting task_for_pid() working. (Note: on A12 you need to take a completely different approach, bazad has proposed an amfid-patch-less-amfid-bypass in here https://github.com/bazad/blanket/tree/master/amfidupe, which will probably work but don't take my word for it). As for the payload dylib, you can just sign it with a legit cert and nobody will complain about the signature. As for unsigned binaries, you'll probably have to sign them with a legit cert as well, due to CoreTrust, or just add to trustcache.

# Credits

- jakeajames for the original jelbrekLib
- theninjaprawn & xerub for patchfinding
- xerub & Electra team for trustcache injection
- stek29 for nvramunlock & lock and hsp4 patch
- theninjaprawn & Ian Beer for dylib injection
- Luca Todesco for the remount patch technique
- Umang Raghuvanshi for the original remount idea
- pwn20wnd for the implementation of the rename-APFS-snapshot technique
- AMFID dylib-less patch technique by Ian Beer reworked with the patch code from Electra's amfid_payload (stek29 & coolstar)
- rootless-hsp4 idea by Ian Beer. Implemented on his updated async_wake exploit
- Sandbox exceptions by stek29 (https://stek29.rocks/2018/01/26/sandbox.html)
- CSBlob patching with stuff from Jonathan Levin and xerub
- The rest of patches are fairly simple and shouldn't be considered property of anyone in my opinion. Everyone who has enough knowledge can write them fairly easily

And, don't forget to tell me if I forgot to credit anyone!