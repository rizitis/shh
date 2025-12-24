![SHH](./shh.png)
Δικαίωμα στην σιωπή... 🤫

---
A tool that embeds arbitrary files into a PNG image with optional password protection, preserves the image as a valid PNG, supports full reversible extraction, and can safely transport the result through text-only channels via Base64 encoding.
---
## Required:

- Debian/Ubuntu:
> apt install libssl-dev

- Fedora/RHEL/CentOS:
> dnf install openssl-devel

- Arch/Manjaro:
> pacman -S openssl

- Slackware:
> The King already has it in the installation, but just in case:
> slackpkg install openssl

- openSUSE:
> zypper install libopenssl-devel

- Alpine:
> apk add openssl-dev

- Gentoo:
> emerge dev-libs/openssl

- Void:
> xbps-install openssl-devel

## Compile:
gcc -O2 -s -o Shh shh.c -lssl -lcrypto


## Usage:
Example to hide the secret.html file in the sbodog.png file: <br>
./Shh hide sbodog.png secret.html output
> Create: output.png + (base64) output.txt
<br>

To revert back:<br>
./Shh decode output.**txt** extracted.html
> or

./Shh decode output.**png** extracted.html

> Password is optional else just hit enter.

---

You can hide everything in your .png:
1. PDF
2. ZIP/TAR
3. MP3/MP4
4. EXE
5. Other PNG/JPG
6. Python scripts
7. bitcoin_wallet.dat
8. etc...

But you can **not** upload the modified output.png on web-hosts that re-encoding images, because your hidden data will be lost.<br>
You **can** upload the base64 output.txt in a pastebin or in file sever or send it via email etc...
<br>
