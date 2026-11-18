# Visual Tools for Reverse Engineering: Deobfuscators

These tools use AST transformations to restore variable names and generate visual control flow graphs for analysis.

Here’s a curated list of deobfuscator websites, organized by the type of code they handle. Most are free and browser-based, which is convenient for quick analysis.

### 🛠️ JavaScript Deobfuscators
These are the most common tools you'll find, as JS is frequently obfuscated on the web.

*   **[deobfuscate.io](https://deobfuscate.io)**: A widely recommended online tool specifically designed to reverse scripts obfuscated by **obfuscator.io**. It's based on the `js-deobfuscator` library.
*   **[de4js](https://lelinhtinh.github.io/de4js)**: Another popular browser-based deobfuscator that focuses on decoding and analyzing obfuscated JavaScript.
*   **[jsunpack.tech](https://jsunpack.tech)**: An AI-powered online tool that uses AST transformations to restore variable names and generate a visual control flow graph for better analysis.
*   **[untwist.dev](https://untwist.dev)**: The browser interface for **Untwist**, a JavaScript deobfuscator, unminifier, and unbundler written in Rust. It's good for turning minified or bundled code back into readable source.
*   **[JSDetox](https://svent.dev/projects/jsdetox/)**: A browser-based online JavaScript deobfuscator.
*   **[JStillery](https://mindedsecurity.github.io/jstillery/)**: Another tool for advanced JS deobfuscation.
*   **[beautifier.io](https://beautifier.io) (JSBeautify)**: While not a true deobfuscator, this tool is essential for **re-indenting** packed or minified code, adding line breaks and spacing to make it readable again.

### ⚡ PowerShell & General-Purpose Deobfuscators
For analyzing malicious scripts, these tools are invaluable.

*   **[CyberChef](https://gchq.github.io/CyberChef)**: **The "Cyber Swiss Army Knife"** for data transformation. It's not a dedicated deobfuscator, but it's arguably the most powerful tool on this list. You can create "recipes" to chain operations (like Base64 decode, XOR, gunzip, etc.) to deobfuscate PowerShell, JavaScript, and VBScript payloads. It runs entirely in your browser and was developed by GCHQ.
*   **MinusOne**: A dedicated deobfuscation engine focused on scripting languages, with strong support for **PowerShell**. The online version is available at [`minusone.skyblue.team`](https://minusone.skyblue.team).
*   **[PowerShell Deobfuscator (cipherssecurity.com)](https://cipherssecurity.com/tools/powershell-deobfuscator/)**: A simple, straightforward online tool where you paste an obfuscated PowerShell or cmd command and get a readable verdict.
*   **[Malware Script De-Obfuscator (zerosuniverse.com)](https://www.zerosuniverse.com/tools/malware-deobfuscator-cyberchef-lite/)**: An interactive console that includes a **PowerShell encodedcommand decoder**, an XOR brute-forcer, and a Base64 unpacker.
*   **[Deobfuscator (inventivehq.com)](https://inventivehq.com/tools/security/malware-deobfuscator)**: A free online tool that auto-detects encoding and can brute-force XOR keys to decode PowerShell payloads.

### 🐍 Other Languages
*   **[PyLingual](https://pylingual.io)**: If you're dealing with obfuscated **Python bytecode** `.pyc` files), this is a dedicated online decompiler that aims to perfectly reconstruct the original source code.

### 💎 Summary for Quick Access
| Tool | Best For | URL |
| :--- | :--- | :--- |
| **CyberChef** | General-purpose data decoding & recipe-based deobfuscation | [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef) |
| **deobfuscate.io** | Scripts obfuscated by obfuscator.io | [deobfuscate.io](https://deobfuscate.io) |
| **MinusOne** | PowerShell & scripting languages | [minusone.skyblue.team](https://minusone.skyblue.team) |
| **de4js** | General JavaScript deobfuscation | [lelinhtinh.github.io/de4js](https://lelinhtinh.github.io/de4js) |
| **PyLingual** | Python bytecode | [pylingual.io](https://pylingual.io) |
