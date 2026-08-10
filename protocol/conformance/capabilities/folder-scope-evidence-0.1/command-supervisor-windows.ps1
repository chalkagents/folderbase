$ErrorActionPreference = "Stop"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom

$nativeSource = @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class FolderbaseKillOnCloseJob
{
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public IntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);

    public static IntPtr Create()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
        }

        var information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        uint size = (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref information, size))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error, "SetInformationJobObject failed");
        }
        return job;
    }

    public static void Assign(IntPtr job, Process process)
    {
        if (!AssignProcessToJobObject(job, process.Handle))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "AssignProcessToJobObject failed");
        }
    }
}
"@

Add-Type -TypeDefinition $nativeSource -Language CSharp

$payloadText = [Console]::In.ReadToEnd()
$payload = $payloadText | ConvertFrom-Json
$job = [IntPtr]::Zero
$worker = $null
$resultLine = $null

try {
    $job = [FolderbaseKillOnCloseJob]::Create()
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $env:FOLDERBASE_NODE_EXECUTABLE
    $escapedWorker = $env:FOLDERBASE_SUPERVISOR_WORKER.Replace('"', '\"')
    $startInfo.Arguments = '"' + $escapedWorker + '"'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $worker = New-Object System.Diagnostics.Process
    $worker.StartInfo = $startInfo
    if (-not $worker.Start()) {
        throw "candidate supervisor worker did not start"
    }

    # The worker blocks on stdin, so assignment completes before it can spawn
    # the candidate. Every later descendant therefore inherits this Job Object.
    [FolderbaseKillOnCloseJob]::Assign($job, $worker)
    $workerInput = [System.IO.StreamWriter]::new(
        $worker.StandardInput.BaseStream,
        $utf8NoBom,
        4096,
        $false)
    $workerOutput = [System.IO.StreamReader]::new(
        $worker.StandardOutput.BaseStream,
        $utf8NoBom,
        $false,
        4096,
        $true)
    $workerError = [System.IO.StreamReader]::new(
        $worker.StandardError.BaseStream,
        $utf8NoBom,
        $false,
        4096,
        $true)
    $workerInput.Write($payloadText)
    $workerInput.Flush()
    $workerInput.Dispose()

    $lineTask = $workerOutput.ReadLineAsync()
    $waitMilliseconds = [Math]::Min([int]::MaxValue, [int64]$payload.timeoutMs + 1500)
    if (-not $lineTask.Wait([int]$waitMilliseconds)) {
        throw "candidate supervisor worker did not return a bounded result"
    }
    $resultLine = $lineTask.Result
    if ([String]::IsNullOrEmpty($resultLine)) {
        $workerErrorText = $workerError.ReadToEnd()
        throw "candidate supervisor worker returned no result: $workerErrorText"
    }
}
finally {
    if ($job -ne [IntPtr]::Zero) {
        [void][FolderbaseKillOnCloseJob]::CloseHandle($job)
    }
    if ($null -ne $worker) {
        [void]$worker.WaitForExit(1000)
        $worker.Dispose()
    }
    if ($null -ne $workerOutput) {
        $workerOutput.Dispose()
    }
    if ($null -ne $workerError) {
        $workerError.Dispose()
    }
}

[Console]::Out.WriteLine($resultLine)
