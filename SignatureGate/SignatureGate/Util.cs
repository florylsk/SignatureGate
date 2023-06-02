//start
using System.Text;
using System.Linq;
using System;
﻿
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace SignatureGate {

    public class Util {
        public static int scanPattern(byte[] _peBytes, byte[] pattern)
        {
            int _max = _peBytes.Length - pattern.Length + 1;
            int j;
            for (int i = 0; i < _max; i++)
            {
                if (_peBytes[i] != pattern[0]) continue;
                for (j = pattern.Length - 1; j >= 1 && _peBytes[i + j] == pattern[j]; j--) ;
                if (j == 0) return i;
            }
            return -1;
        }

        public static void WriteFile(string filename, byte[] rawData)
        {
            FileStream fs = new FileStream(filename, FileMode.OpenOrCreate);
            fs.Write(rawData, 0, rawData.Length);
            fs.Close();
        }


        public static byte[] Read(string filePath)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] rawData = new byte[stream.Length];
                stream.Read(rawData, 0, (int)stream.Length);
                stream.Close();

                return rawData;
            }
        }


        public static byte[] Decrypt(byte[] data, string encKey)
        {
            byte[] T = new byte[256];
            byte[] S = new byte[256];
            int keyLen = encKey.Length;
            int dataLen = data.Length;
            byte[] result = new byte[dataLen];
            byte tmp;
            int j = 0, t = 0, i = 0;


            for (i = 0; i < 256; i++)
            {
                S[i] = Convert.ToByte(i);
                T[i] = Convert.ToByte(encKey[i % keyLen]);
            }

            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                tmp = S[j];
                S[j] = S[i];
                S[i] = tmp;
            }
            j = 0;
            for (int x = 0; x < dataLen; x++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                tmp = S[j];
                S[j] = S[i];
                S[i] = tmp;

                t = (S[i] + S[j]) % 256;

                result[x] = Convert.ToByte(data[x] ^ S[t]);
            }

            return result;
        }

        public struct APITableEntry {
            public string Name;
            public Int64 Address;
            public Int16 Syscall;
            public UInt64 Hash;
        }

        public static UInt64 NtAllocateVirtualMemoryHash { get; } = 0xf5bd373480a6b89b;

        public static UInt64 NtProtectVirtualMemoryHash { get; } = 0x858bcb1046fb6a37;

        public static UInt64 NtCreateThreadExHash { get; } = 0x64dc7db288c5015f;

        public static UInt64 NtWaitForSingleObjectHash { get; } = 0xc6a2fa174e551bcb;


        /// <param name=new string("gsm".ToCharArray().Reverse().ToArray())>Message to log.</param>
        /// <param name=new string("tnedni".ToCharArray().Reverse().ToArray())>Indentation level.</param>
        /// <param name=new string("xiferp".ToCharArray().Reverse().ToArray())>Message prefix.</param>
        public static void LogInfo(string msg, int indent = 0, string prefix = "[>]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Blue);
#endif
        }

        /// <param name=new string("gsm".ToCharArray().Reverse().ToArray())>Message to log.</param>
        /// <param name=new string("tnedni".ToCharArray().Reverse().ToArray())>Indentation level.</param>
        /// <param name=new string("xiferp".ToCharArray().Reverse().ToArray())>Message prefix.</param>
        public static void LogError(string msg, int indent = 0, string prefix = "[-]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Red);
#endif
        }

        /// <param name=new string("gsm".ToCharArray().Reverse().ToArray())>Message to log.</param>
        /// <param name=new string("tnedni".ToCharArray().Reverse().ToArray())>Indentation level.</param>
        /// <param name=new string("xiferp".ToCharArray().Reverse().ToArray())>Message prefix</param>
        public static void LogSuccess(string msg, int indent = 0, string prefix = "[+]") {
#if DEBUG
            if (string.IsNullOrEmpty(msg))
                return;

            LogMessage(msg, prefix, indent, ConsoleColor.Green);
#endif
        }

        /// <param name=new string("gsm".ToCharArray().Reverse().ToArray())>Message to log.</param>
        /// <param name=new string("tnedni".ToCharArray().Reverse().ToArray())>Indentation level.</param>
        /// <param name=new string("xiferp".ToCharArray().Reverse().ToArray())>Message prefix.</param>
        /// <param name=new string("roloc".ToCharArray().Reverse().ToArray())>The color of the prifix on the console.</param>
        private static void LogMessage(string msg, string prefix, int indent, ConsoleColor color) {
            Console.Write(new String(' ', indent));
            Trace.Write(new String(' ', indent));

            Trace.Write(prefix);
            Console.ForegroundColor = color;
            Console.Write(prefix);
            Console.ResetColor();

            Console.WriteLine($" {msg}");
            Trace.WriteLine($" {msg}");
        }


        /// <param name=new string("emaNnoitcnuF".ToCharArray().Reverse().ToArray())>The ASCII name of a function.</param>
        public static UInt64 GetFunctionDJB2Hash(string FunctionName) {
            if (string.IsNullOrEmpty(FunctionName))
                return 0;

            UInt64 hash = 0x7734773477347734;
            foreach (char c in FunctionName)
                hash = ((hash << 0x5) + hash) + (byte)c;

            return hash;
        }

    }

    public class ArgumentParser
    {
        private StringDictionary Parameters;

        public ArgumentParser(string[] Args)
        {
            Parameters = new StringDictionary();
            Regex Spliter = new Regex(@"^-{1,2}",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            Regex Remover = new Regex(@"^['""]?(.*?)['""]?$",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            string Parameter = null;
            string[] Parts;

            foreach (string Txt in Args)
            {
                Parts = Spliter.Split(Txt, 3);

                switch (Parts.Length)
                {
                    case 1:
                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                            {
                                Parts[0] =
                                    Remover.Replace(Parts[0], "$1");

                                Parameters.Add(Parameter, Parts[0]);
                            }
                            Parameter = null;
                        }

                        break;

                    case 2:

                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                                Parameters.Add(Parameter, new string(new string("true".ToCharArray().Reverse().ToArray()).ToCharArray().Reverse().ToArray()));
                        }
                        Parameter = Parts[1];
                        break;

                    case 3:
                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                                Parameters.Add(Parameter, new string(new string("true".ToCharArray().Reverse().ToArray()).ToCharArray().Reverse().ToArray()));
                        }

                        Parameter = Parts[1];

                        if (!Parameters.ContainsKey(Parameter))
                        {
                            Parts[2] = Remover.Replace(Parts[2], "$1");
                            Parameters.Add(Parameter, Parts[2]);
                        }

                        Parameter = null;
                        break;
                }
            }
            if (Parameter != null)
            {
                if (!Parameters.ContainsKey(Parameter))
                    Parameters.Add(Parameter, new string(new string("true".ToCharArray().Reverse().ToArray()).ToCharArray().Reverse().ToArray()));
            }
        }

        public string this[string Param]
        {
            get
            {
                return (Parameters[Param]);
            }
        }

        public string GetOrDefault(string key, string defaultValue)
        {
            if (!Parameters.ContainsKey(key))
            {
                return defaultValue;
            }

            return Parameters[key];
        }
    }
}
