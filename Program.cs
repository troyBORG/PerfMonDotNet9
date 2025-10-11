// Program.cs — .NET 9 minimal API, class-based (no top-level statements).
// Endpoint: /perf-stats  (CSV only)
// CSV columns:
// cpu_percent, core_percent, mem_total, mem_avail, total_bytes_sent, total_bytes_received, bps_sent, bps_received
//
// Behavior:
// - No args: system-wide CPU% and core% (true per-core max on each OS), memory, and network.
// - With --procs "A;B;C": CPU% is the sum of those processes; core% ~= sum * logical_cores (capped at 100).
//   Memory and network stay system-wide. Endpoint/CSV unchanged.
//
// Also provides / (redirect to /index.html), /index.html (optional), /reset-counters.

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace PerfMonDotNet9;

internal static class Program
{
    // ===== State =====
    private static long _initialBytesSent;
    private static long _initialBytesRecv;
    private static long _prevBytesSent;
    private static long _prevBytesRecv;
    private static DateTime _prevTime = DateTime.UtcNow;

    private static string[] _procFilters = Array.Empty<string>();

    public static async Task Main(string[] args)
    {
        _procFilters = ParseListArg(args, "--procs", "-p");

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args });
        builder.WebHost.UseKestrel(opt => opt.Listen(IPAddress.Any, 8082));
        var app = builder.Build();

        ResetCounters();

        // / -> /index.html
        app.MapGet("/", (HttpContext ctx) =>
        {
            ctx.Response.StatusCode = StatusCodes.Status301MovedPermanently;
            ctx.Response.Headers.Location = "/index.html";
            return Task.CompletedTask;
        });

        // index.html (optional)
        app.MapGet("/index.html", async ctx =>
        {
            var path = Path.Combine(AppContext.BaseDirectory, "index.html");
            if (File.Exists(path))
            {
                ctx.Response.ContentType = "text/html; charset=utf-8";
                await ctx.Response.SendFileAsync(path);
            }
            else
            {
                ctx.Response.StatusCode = 404;
                await ctx.Response.WriteAsync("index.html not found");
            }
        });

        // reset counters
        app.MapGet("/reset-counters", async ctx =>
        {
            ResetCounters();
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync("Bandwidth counters reset");
        });

        // perf-stats (CSV)
        app.MapGet("/perf-stats", async ctx =>
        {
            var sample = TimeSpan.FromSeconds(1);

            double cpuPercent;
            double corePercent;

            if (_procFilters.Length == 0)
            {
                // system-wide
                cpuPercent  = await SampleSystemCpuPercentAsync(sample);
                corePercent = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                    ? await SampleLinuxMaxCorePercentAsync(sample)
                    : await SampleWindowsMaxCorePercentAsync(sample, cpuPercent);
            }
            else
            {
                // filtered: sum CPU% across matching processes;
                // core ~= worst single-core saturation those could induce
                // ≈ sumCPU * logical_cores, capped at 100.
                cpuPercent  = await SampleFilteredCpuPercentAsync(sample, _procFilters);
                corePercent = Math.Min(100.0, cpuPercent * Math.Max(1, Environment.ProcessorCount)); // <-- only changed line
            }

            var (memTotalBytes, memAvailBytes) = GetSystemMemoryBytes();

            long totalSentSinceStart = GetSystemBytesSent() - _initialBytesSent;
            long totalRecvSinceStart = GetSystemBytesRecv() - _initialBytesRecv;

            var now = DateTime.UtcNow;
            double elapsed = (now - _prevTime).TotalSeconds;
            if (elapsed <= 0) elapsed = 1e-3;

            long deltaSent = totalSentSinceStart - _prevBytesSent;
            long deltaRecv = totalRecvSinceStart - _prevBytesRecv;

            double bpsSent = deltaSent >= 0 ? deltaSent / elapsed : 0;
            double bpsRecv = deltaRecv >= 0 ? deltaRecv / elapsed : 0;

            _prevBytesSent = totalSentSinceStart;
            _prevBytesRecv = totalRecvSinceStart;
            _prevTime = now;

            string csv =
                $"{cpuPercent}, {corePercent}, {memTotalBytes}, {memAvailBytes}, {totalSentSinceStart}, {totalRecvSinceStart}, {bpsSent}, {bpsRecv}";

            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync(csv);
        });

        await app.RunAsync();
    }

    // ===== Helpers =====

    private static void ResetCounters()
    {
        _initialBytesSent = GetSystemBytesSent();
        _initialBytesRecv = GetSystemBytesRecv();
        _prevBytesSent = 0;
        _prevBytesRecv = 0;
        _prevTime = DateTime.UtcNow;
    }

    private static long GetSystemBytesSent()
    {
        long sum = 0;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!IncludeNic(ni)) continue;
            try { sum += ni.GetIPv4Statistics().BytesSent; } catch { }
        }
        return sum;
    }

    private static long GetSystemBytesRecv()
    {
        long sum = 0;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!IncludeNic(ni)) continue;
            try { sum += ni.GetIPv4Statistics().BytesReceived; } catch { }
        }
        return sum;
    }

    // Prefer real/primary NICs: up, not loopback, not virtual/filter, has IPv4 default gateway
    private static bool IncludeNic(NetworkInterface ni)
    {
        if (ni == null) return false;
        if (ni.OperationalStatus != OperationalStatus.Up) return false;
        if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) return false;

        var s = ((ni.Name ?? "") + " " + (ni.Description ?? "")).ToLowerInvariant();
        string[] bad = {
            "virtual", "vmware", "hyper-v", "vethernet", "switch", "host-only",
            "npcap", "tailscale", "bridge", "bluetooth", "wireguard", "wg ", "zerotier",
            "virtualbox", "pppoe", "teredo", "ip-https", "6to4", "wan miniport",
            "ndis", "filter", "qos", "network monitor", "kernel debug", "xbox"
        };
        foreach (var m in bad) if (s.Contains(m)) return false;

        try
        {
            var props = ni.GetIPProperties();
            foreach (var gw in props.GatewayAddresses)
            {
                if (gw?.Address != null && gw.Address.AddressFamily == AddressFamily.InterNetwork)
                    return true;
            }
        }
        catch { }

        return false;
    }

    private static (long total, long available) GetSystemMemoryBytes()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            try
            {
                long total = 0, avail = 0;
                foreach (var line in File.ReadLines("/proc/meminfo"))
                {
                    if (line.StartsWith("MemTotal:")) total = ParseKiBLine(line);
                    else if (line.StartsWith("MemAvailable:")) avail = ParseKiBLine(line);
                    if (total > 0 && avail > 0) break;
                }
                return (total, avail);
            }
            catch { }
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                var m = new NativeMethods.MEMORYSTATUSEX();
                if (NativeMethods.GlobalMemoryStatusEx(m))
                    return ((long)m.ullTotalPhys, (long)m.ullAvailPhys);
            }
            catch { }
        }

        // fallback
        var info = GC.GetGCMemoryInfo();
        long approxTotal = info.TotalAvailableMemoryBytes > 0 ? info.TotalAvailableMemoryBytes : 0;
        long approxAvail = approxTotal > 0 ? approxTotal - Process.GetCurrentProcess().WorkingSet64 : 0;
        return (approxTotal, approxAvail);

        static long ParseKiBLine(string line)
        {
            var parts = line.Split(':', 2);
            if (parts.Length < 2) return 0;
            var digits = new string(parts[1].Where(char.IsDigit).ToArray());
            return long.TryParse(digits, out var kib) ? kib * 1024 : 0;
        }
    }

    // overall CPU% via total process times (cross-platform)
    private static async Task<double> SampleSystemCpuPercentAsync(TimeSpan sample)
    {
        var t0 = GetTotalCpuTimeAllProcs();
        var start = DateTime.UtcNow;
        await Task.Delay(sample);
        var t1 = GetTotalCpuTimeAllProcs();

        var elapsed = (DateTime.UtcNow - start).TotalSeconds;
        if (elapsed <= 0) return 0;

        var cpuDelta = (t1 - t0).TotalSeconds;
        var logical = Math.Max(1, Environment.ProcessorCount);
        var pct = (cpuDelta / (elapsed * logical)) * 100.0;
        return Clamp01(pct);

        static TimeSpan GetTotalCpuTimeAllProcs()
        {
            TimeSpan sum = TimeSpan.Zero;
            foreach (var p in Process.GetProcesses())
            {
                try { sum += p.TotalProcessorTime; } catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return sum;
        }

        static double Clamp01(double v) => v < 0 ? 0 : (v > 100 ? 100 : v);
    }

    // filtered CPU%: sum of matching processes over the sample window
    private static async Task<double> SampleFilteredCpuPercentAsync(TimeSpan sample, string[] filters)
    {
        var t0 = new Dictionary<int, TimeSpan>();

        foreach (var p in GetMatchingProcesses(filters))
        {
            try { t0[p.Id] = p.TotalProcessorTime; }
            catch { }
            finally { try { p.Dispose(); } catch { } }
        }

        await Task.Delay(sample);

        int logical = Math.Max(1, Environment.ProcessorCount);
        double sum = 0;

        foreach (var p in GetMatchingProcesses(filters))
        {
            try
            {
                var pid = p.Id;
                if (!t0.TryGetValue(pid, out var a)) continue;
                var b = p.TotalProcessorTime;

                double cpuPct = 0;
                if (b > a && sample.TotalSeconds > 0)
                {
                    cpuPct = (b - a).TotalSeconds / (sample.TotalSeconds * logical) * 100.0;
                    cpuPct = Math.Clamp(cpuPct, 0, 100);
                }
                sum += cpuPct;
            }
            catch { }
            finally { try { p.Dispose(); } catch { } }
        }

        return sum;
    }

    private static IEnumerable<Process> GetMatchingProcesses(string[] filters)
    {
        var all = Process.GetProcesses();
        if (filters is null || filters.Length == 0) return all;

        return all.Where(p =>
        {
            try
            {
                var n = p.ProcessName;
                foreach (var f in filters)
                {
                    if (n.Equals(f, StringComparison.OrdinalIgnoreCase)) return true;
                    if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        n.AsSpan(0, n.Length - 4).Equals(f.AsSpan(), StringComparison.OrdinalIgnoreCase)) return true;
                    if (n.Contains(f, StringComparison.OrdinalIgnoreCase)) return true;

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                    {
                        // Linux: match cmdline substring (e.g., "dotnet Resonite.dll")
                        try
                        {
                            var bytes = File.ReadAllBytes($"/proc/{p.Id}/cmdline");
                            if (bytes.Length > 0)
                            {
                                var parts = System.Text.Encoding.UTF8.GetString(bytes).Split('\0', StringSplitOptions.RemoveEmptyEntries);
                                var cmd = string.Join(' ', parts);
                                if (!string.IsNullOrEmpty(cmd) && cmd.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) return true;
                            }
                        }
                        catch { }
                    }
                }
                return false;
            }
            catch { return false; }
        }).ToArray();
    }

    // Linux: true max per-core via /proc/stat
    private static async Task<double> SampleLinuxMaxCorePercentAsync(TimeSpan sample)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return 0;

        var a = ReadProcStatPerCore();
        await Task.Delay(sample);
        var b = ReadProcStatPerCore();

        double maxPct = 0;
        foreach (var key in a.Keys)
        {
            if (!b.TryGetValue(key, out var end)) continue;
            var start = a[key];

            ulong idleA = start.idle + start.iowait;
            ulong idleB = end.idle + end.iowait;
            ulong totalA = start.Total();
            ulong totalB = end.Total();
            ulong totalDiff = totalB - totalA;
            ulong idleDiff = idleB - idleA;
            if (totalDiff == 0) continue;

            double usage = (double)(totalDiff - idleDiff) / totalDiff * 100.0;
            if (usage > maxPct) maxPct = usage;
        }
        if (maxPct < 0) maxPct = 0;
        if (maxPct > 100) maxPct = 100;
        return maxPct;

        static Dictionary<string, CpuLine> ReadProcStatPerCore()
        {
            var dict = new Dictionary<string, CpuLine>(StringComparer.Ordinal);
            foreach (var line in File.ReadLines("/proc/stat"))
            {
                if (!line.StartsWith("cpu")) continue;
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 8) continue;

                string id = parts[0];
                if (id == "cpu") continue; // skip aggregate

                ulong ParseAt(int idx) => idx < parts.Length && ulong.TryParse(parts[idx], out var v) ? v : 0UL;

                var cl = new CpuLine
                {
                    user = ParseAt(1),
                    nice = ParseAt(2),
                    system = ParseAt(3),
                    idle = ParseAt(4),
                    iowait = ParseAt(5),
                    irq = ParseAt(6),
                    softirq = ParseAt(7),
                    steal = ParseAt(8),
                    guest = ParseAt(9),
                    guest_nice = ParseAt(10),
                };
                dict[id] = cl;
            }
            return dict;
        }
    }

    // Windows: true max per-core via PerformanceCounter (compile only for net9.0-windows)
#if WINDOWS
    private static async Task<double> SampleWindowsMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
    {
        try
        {
            var cat = new System.Diagnostics.PerformanceCounterCategory("Processor");
            var instances = cat.GetInstanceNames()
                            .Where(n => !string.Equals(n, "_Total", StringComparison.OrdinalIgnoreCase))
                            .ToArray();
            if (instances.Length == 0) return fallbackOverall;

            var counters = new List<System.Diagnostics.PerformanceCounter>(instances.Length);
            try
            {
                foreach (var inst in instances)
                    counters.Add(new System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", inst, readOnly: true));

                // prime
                foreach (var c in counters) _ = c.NextValue();
                await Task.Delay(sample);

                double max = 0;
                foreach (var c in counters)
                {
                    var v = c.NextValue();
                    if (v > max) max = v;
                }
                return Math.Clamp(max, 0, 100);
            }
            finally
            {
                foreach (var c in counters) c.Dispose();
            }
        }
        catch
        {
            return fallbackOverall;
        }
    }
#else
    // Non-Windows builds (e.g., net9.0 for Linux) never touch PerformanceCounter
    private static Task<double> SampleWindowsMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
        => Task.FromResult(fallbackOverall);
#endif

    private static string[] ParseListArg(string[] args, params string[] keys)
    {
        if (args == null || args.Length == 0) return Array.Empty<string>();
        for (int i = 0; i < args.Length; i++)
        {
            foreach (var k in keys)
            {
                if (args[i].Equals(k, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        return SplitList(args[i + 1]);
                    return Array.Empty<string>();
                }
                if (args[i].StartsWith(k + "=", StringComparison.OrdinalIgnoreCase))
                    return SplitList(args[i].Substring(k.Length + 1));
            }
        }
        return Array.Empty<string>();

        static string[] SplitList(string s)
            => s.Split(new[] { ';', ',', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .Where(x => x.Length > 0)
                .ToArray();
    }

    // ===== Types =====

    private struct CpuLine
    {
        public ulong user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
        public ulong Total() => user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
    }

    private static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal class MEMORYSTATUSEX
        {
            public uint dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);
    }
}
