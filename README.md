# SignatureGate

Weaponized version of HellsGate, bypassing AV/EDR/EPPs by abusing opt-in-fix CVE-2013-3900. Most code is from https://github.com/am0nsec/SharpHellsGate and https://github.com/med0x2e/SigFlip.

Disclaimer: The information/files provided in this repository are strictly intended for educational and ethical purposes only. The techniques and tools are intended to be used in a lawful and responsible manner, with the explicit consent of the target system's owner. Any unauthorized or malicious use of these techniques and tools is strictly prohibited and may result in legal consequences. I am not responsible for any damages or legal issues that may arise from the misuse of the information provided.

## Usage

Generate shellcode from a .NET assembly with Donut.

Generate malicious signed file with:


```
.\SigFlip.exe -i path_to_signed_binary -s path_to_malicious_shellcode -o path_to_output_file -e encryption_key
```

Run the malicious shellcode from the file with

```
.\SignatureGate.exe path_to_malicious_file encryption_key
```

## Proof of Concept

![SignatureGate](https://github.com/florylsk/SignatureGate/assets/46110263/1e89b761-3a6e-42d9-b15f-96ab70f011c7)
