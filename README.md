# Nibiru Ransomware Variant Decryptor

### Ransomware

Nibiru ransomware is a super-badly written ransomware. It traverses directories and encrypts files with Rijndael-256. After encryption, the files are given an extension, `.Nibiru`.

It targets files with extensions: `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.jpg`, `.jpeg`, `.png`, `.psd`, `.txt`, `.zip`, `.rar`, `.html`, `.php`, `.asp`, `.aspx`, `.mp4`, `.avi`, `.3gp`, `.wmv`, `.MOV`, `.mp3`, `.wav`, `.flac`, `.wma`, `.mov`, `.raw`, `.apk`, `.encrypt`, `.crypted`, `.ahok`, `.cs`, `.vb`

It skips critical directories like `Program Files`, `Windows`, `System Volume Information`, etc.

Example hash: e0a681902f4f331582670e535a7d1eb3d6eff18d3fbed3ffd2433f898219576f

### Weak encryption

Rijndael-256 is a secure encryption algorithm. However, Nibiru uses a hardcoded string, `Nibiru` to compute the 32-byte key and 16-byte IV values. This weakness is leveraged by the decryptor program to decrypt files encrypted by this variant.

### Compiling

The solution has been tested using Visual Studio Community 2019 v16.7.6 on Windows 10 running .NET Framework v4.8.03752. No additional packages are neccessary to compile.