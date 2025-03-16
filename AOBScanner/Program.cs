using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AOBScanner
{
    // Classe para representar um conjunto de 3 padrões, com nome do endereço
    class PatternSet
    {
        public string Name { get; set; }         
        public string AddressName { get; set; }  
        public byte[] Pattern1 { get; set; }
        public byte[] Pattern2 { get; set; }
        public byte[] Pattern3 { get; set; }

        public PatternSet(string name, string addressName, byte[] pattern1, byte[] pattern2, byte[] pattern3)
        {
            Name = name;
            AddressName = addressName;
            Pattern1 = pattern1;
            Pattern2 = pattern2;
            Pattern3 = pattern3;
        }
    }

    class Program
    {
        // Importações P/Invoke
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        // Constantes
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        static void Main(string[] args)
        {
            // Nome do processo alvo
            string processName = "Game.exe";

            // Lista de conjuntos de padrões a buscar
            List<PatternSet> patternSets = new List<PatternSet>
            {
                // Exemplo original (você pode substituir os padrões)
                new PatternSet(
                "InjectionPoint1",
                    "ABS",
                    new byte[] { 0x8B, 0x8D, 0x14, 0xFF, 0xFF, 0xFF },
                    new byte[] { 0x03, 0x8D, 0x74, 0xFF, 0xFF, 0xFF },
                    new byte[] { 0x89, 0x86, 0xF4 , 0x00, 0x00, 0x00 }
                ),
                new PatternSet(
                   "InjectionPoint2",
                    "Defesa",
                    new byte[] { 0xF3, 0x0F, 0x11, 0x45, 0xD0 },
                    new byte[] { 0x03, 0x85, 0x7C, 0xFF, 0xFF, 0xFF },
                    new byte[] { 0x89, 0x81, 0xEC , 0x00, 0x00, 0x00 }
                ),
                // Adicione os outros aqui com seus respectivos padrões
                new PatternSet("InjectionPoint3", "TravaRES", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint4", "MinDamage", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint5", "MaxDamage", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint6", "Abs", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint7", "Defesa", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint8", "HPTotal", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint9", "AtackSpeed", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint10", "RangeAtack", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint11", "VelSpeed", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint12", "Critico", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint13", "Block", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint14", "AddPeso", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint15", "BugTime", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint16", "LockItem", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint17", "EditLvl", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint18", "status", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint19", "ATA", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint20", "FS", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint21", "vigo1", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ }),
                new PatternSet("InjectionPoint22", "vigo2", new byte[] { /* padrão1 */ }, new byte[] { /* padrão2 */ }, new byte[] { /* padrão3 */ })
            };

            Console.WriteLine("Iniciando AOB Scanner...");
            try
            {
                // Encontra o processo
                Process[] processes = Process.GetProcessesByName(processName.Replace(".exe", ""));
                if (processes.Length == 0)
                {
                    Console.WriteLine($"Processo {processName} não encontrado.");
                    return;
                }
                Process process = processes[0];
                Console.WriteLine($"Processo {processName} encontrado! PID: {process.Id}");

                // Abre o processo
                IntPtr processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, process.Id);
                if (processHandle == IntPtr.Zero)
                {
                    Console.WriteLine("Erro ao abrir o processo. Execute como administrador.");
                    return;
                }

                // Obtém o módulo principal
                ProcessModule mainModule = process.MainModule;
                IntPtr baseAddress = mainModule.BaseAddress;
                int moduleSize = mainModule.ModuleMemorySize;

                Console.WriteLine($"Módulo base: 0x{baseAddress.ToInt64():X8}, Tamanho: {moduleSize} bytes");

                // Buffer para leitura da memória
                byte[] memoryBuffer = new byte[moduleSize];
                int bytesRead;

                // Lê a memória
                bool success = ReadProcessMemory(processHandle, baseAddress, memoryBuffer, moduleSize, out bytesRead);
                if (!success || bytesRead != moduleSize)
                {
                    Console.WriteLine("Erro ao ler a memória do processo.");
                    CloseHandle(processHandle);
                    return;
                }

                // Busca cada conjunto de padrões
                foreach (var patternSet in patternSets)
                {
                    IntPtr foundAddress = FindConsecutivePatterns(memoryBuffer, patternSet.Pattern1, patternSet.Pattern2, patternSet.Pattern3, baseAddress);
                    if (foundAddress != IntPtr.Zero)
                    {
                        // Formata o endereço como <AddressName>:<XXXXXXXX>
                        string formattedAddress = $"{patternSet.AddressName}:{foundAddress.ToInt64():X8}";
                        Console.WriteLine(formattedAddress);
                    }
                    else
                    {
                        Console.WriteLine($"{patternSet.AddressName}:Não encontrado");
                    }
                }

                // Fecha o handle
                CloseHandle(processHandle);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erro: {ex.Message}");
            }

            Console.WriteLine("\nPressione qualquer tecla para sair...");
            Console.ReadKey();
        }

        // Função para buscar 3 padrões consecutivos e retornar o endereço do terceiro
        static IntPtr FindConsecutivePatterns(byte[] memory, byte[] pattern1, byte[] pattern2, byte[] pattern3, IntPtr baseAddress)
        {
            int pattern1Length = pattern1.Length;
            int pattern2Length = pattern2.Length;
            int pattern3Length = pattern3.Length;

            for (int i = 0; i <= memory.Length - (pattern1Length + pattern2Length + pattern3Length); i++)
            {
                if (MatchesPattern(memory, i, pattern1))
                {
                    int secondOffset = i + pattern1Length;
                    if (MatchesPattern(memory, secondOffset, pattern2))
                    {
                        int thirdOffset = secondOffset + pattern2Length;
                        if (MatchesPattern(memory, thirdOffset, pattern3))
                        {
                            return IntPtr.Add(baseAddress, thirdOffset);
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }

        // Função auxiliar para verificar se um padrão corresponde
        static bool MatchesPattern(byte[] memory, int offset, byte[] pattern)
        {
            if (offset + pattern.Length > memory.Length) return false;

            for (int j = 0; j < pattern.Length; j++)
            {
                if (memory[offset + j] != pattern[j])
                {
                    return false;
                }
            }
            return true;
        }
    }
}