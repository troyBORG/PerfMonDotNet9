
// Program.cs — .NET 9 drop‑in with process filtering + NIC filtering
// New in this build:
//   - --procs "Name1;Name2;Substr3"   : restrict /proc-stats to these processes
//   - --nics "eth0;Ethernet"          : only count these interfaces for system net stats
//   - --nic-mode max|sum (default: max) : aggregate across selected NICs by taking MAX bps or SUM
//   - --include-virtual               : include virtual/tunnel/bridge NICs (default: excluded)
//   - GET /proc-stats                 : per-process CPU/RSS (+ Linux disk IO bps)
//   - GET /resonite                   : alias for /proc-stats if --procs is supplied
//   - GET /sys-stats                  : JSON system stats (safer than the CSV)
//   - GET /debug/nics                 : enumerate NICs and indicate which are included
//
// NOTE: per-process network B/s is NOT portable without privileged helpers (ETW/eBPF).
// This build keeps system-wide net B/s and per-process CPU/RSS (and Linux /proc/<pid>/io).

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace PerfMonDotNet9;

internal static class Program
{
    // ===== State (system totals) =====
    private static DateTime _prevTime = DateTime.UtcNow;

    // Per-NIC "since-start" baselines and previous totals (bytes)
    private static readonly Dictionary<string, (long sent0, long recv0)> _nicStart = new();
    private static readonly Dictionary<string, (long sentPrev, long recvPrev)> _nicPrev = new();

    // ===== Proc filtering =====
    private static readonly StringComparer CI = StringComparer.OrdinalIgnoreCase;
    private static string[] _procFilters = Array.Empty<string>();

    // ===== NIC filtering =====
    private static string[] _nicFilters = Array.Empty<string>();
    private static bool _includeVirtual = false;
    private static bool _nicSumMode = false;

    public static async Task Main(string[] args)
    {
        _procFilters = ParseListArg(args, "--procs", "-p");
        _nicFilters  = ParseListArg(args, "--nics", "--nic");
        _includeVirtual = HasFlag(args, "--include-virtual");
        var nicMode = GetArg(args, "--nic-mode");
        _nicSumMode = nicMode != null && nicMode.Equals("sum", StringComparison.OrdinalIgnoreCase);

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args });
        builder.WebHost.UseKestrel(opt => opt.Listen(IPAddress.Any, 8082));
        var app = builder.Build();

        ResetNicBaselines();

        Console.WriteLine("=== PerfMonDotNet9 ===");
        Console.WriteLine($"Filters: procs=[{string.Join(", ", _procFilters)}], nics=[{string.Join(", ", _nicFilters)}], includeVirtual={_includeVirtual}, nicMode={(_nicSumMode ? "sum" : "max")}");
        foreach (var info in EnumerateNics())
            Console.WriteLine($"NIC: {(info.include ? "[*]" : "[ ]")} {info.name} | {info.desc} | Type={info.type} | Up={info.up}");

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

        // NIC debug
        app.MapGet("/debug/nics", async ctx =>
        {
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync(JsonSerializer.Serialize(EnumerateNics(), new JsonSerializerOptions{WriteIndented=true}));
        });

        // Reset counters
        app.MapGet("/reset-counters", async ctx =>
        {
            ResetNicBaselines();
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync("Bandwidth counters reset");
        });

        // ===== System stats (CSV) kept for backward compat =====
        // CSV: cpuOverall, cpuMaxCore, memTotalBytes, memAvailBytes, totalSentSinceStart, totalRecvSinceStart, bpsSentBytes, bpsRecvBytes
        app.MapGet("/perf-stats", async ctx =>
        {
            var csv = await BuildSystemCsvAsync();
            ctx.Response.ContentType = "text/plain";
            await ctx.Response.WriteAsync(csv);
        });

        // ===== System stats (JSON) — preferred to avoid column-order mistakes =====
        app.MapGet("/sys-stats", async ctx =>
        {
            var json = await BuildSystemJsonAsync();
            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync(json);
        });

        // ===== Per-process stats (JSON) =====
        app.MapGet("/proc-stats", async ctx =>
        {
            var sample = TimeSpan.FromSeconds(1);
            var targets = GetMatchingProcesses(_procFilters);

            // snapshot T0
            var t0 = new Dictionary<int, TimeSpan>();
            var rss0 = new Dictionary<int, long>();
            var cmd = new Dictionary<int, string?>();
            foreach (var p in targets)
            {
                try
                {
                    t0[p.Id] = p.TotalProcessorTime;
                    rss0[p.Id] = SafeWorkingSet(p);
                    cmd[p.Id] = TryReadCmdline(p);
                }
                catch { }
                finally { SafeDispose(p); }
            }

            await Task.Delay(sample);

            // snapshot T1 and compute
            var result = new List<object>();
            double elapsed = sample.TotalSeconds;
            int logical = Math.Max(1, Environment.ProcessorCount);

            foreach (var p in GetMatchingProcesses(_procFilters))
            {
                try
                {
                    var pid = p.Id;
                    var name = SafeName(p);

                    t0.TryGetValue(pid, out var a);
                    var b = p.TotalProcessorTime;

                    double cpuPct = 0;
                    if (a != default && b > a && elapsed > 0)
                    {
                        cpuPct = (b - a).TotalSeconds / (elapsed * logical) * 100.0;
                        if (cpuPct < 0) cpuPct = 0;
                        if (cpuPct > 100) cpuPct = 100;
                    }

                    long rss = SafeWorkingSet(p);
                    string? cmdline = cmd.TryGetValue(pid, out var s) ? s : TryReadCmdline(p);

                    (double rdBps, double wrBps) = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                        ? LinuxIoBps(pid)
                        : (0d, 0d);

                    result.Add(new
                    {
                        pid,
                        name,
                        cpu_percent = Math.Round(cpuPct, 2),
                        rss_bytes = rss,
                        io_read_bps = Math.Round(rdBps, 2),
                        io_write_bps = Math.Round(wrBps, 2),
                        cmdline
                    });
                }
                catch { }
                finally { SafeDispose(p); }
            }

            var payload = new
            {
                filters = _procFilters,
                processes = result.OrderByDescending(x => ((dynamic)x).cpu_percent).ToArray()
            };

            ctx.Response.ContentType = "application/json; charset=utf-8";
            await ctx.Response.WriteAsync(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        });

        // convenience alias when filters are provided
        if (_procFilters.Length > 0)
        {
            app.MapGet("/resonite", async ctx =>
            {
                ctx.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
                ctx.Response.Headers.Location = "/proc-stats";
                await Task.CompletedTask;
            });
        }

        await app.RunAsync();
    }

    // ===== System stat builders =====

    private static async Task<string> BuildSystemCsvAsync()
    {
        var sample = TimeSpan.FromSeconds(1);

        double cpuPercent = await SampleSystemCpuPercentAsync(sample);
        double corePercent = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            ? await SampleLinuxMaxCorePercentAsync(sample)
            : await SampleWindowsMaxCorePercentAsync(sample, cpuPercent);

        var (memTotalBytes, memAvailBytes) = GetSystemMemoryBytes();

        var (totalSent, totalRecv, bpsSent, bpsRecv) = SampleNetwork();

        string csv =
            $"{cpuPercent}, {corePercent}, {memTotalBytes}, {memAvailBytes}, {totalSent}, {totalRecv}, {bpsSent}, {bpsRecv}";

        return csv;
    }

    private static async Task<string> BuildSystemJsonAsync()
    {
        var sample = TimeSpan.FromSeconds(1);

        double cpuPercent = await SampleSystemCpuPercentAsync(sample);
        double corePercent = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
            ? await SampleLinuxMaxCorePercentAsync(sample)
            : await SampleWindowsMaxCorePercentAsync(sample, cpuPercent);

        var (memTotalBytes, memAvailBytes) = GetSystemMemoryBytes();

        var (totalSent, totalRecv, bpsSent, bpsRecv) = SampleNetwork();

        var payload = new
        {
            cpu = new { overall_percent = cpuPercent, max_core_percent = corePercent },
            memory = new { total_bytes = memTotalBytes, available_bytes = memAvailBytes },
            network = new
            {
                bps_sent_bytes = bpsSent,
                bps_recv_bytes = bpsRecv,
                totals_since_start = new { sent_bytes = totalSent, recv_bytes = totalRecv },
                nic_mode = _nicSumMode ? "sum" : "max",
                included_nics = EnumerateNics().Where(n => n.include).Select(n => n.name).ToArray()
            }
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    // Returns (totalSentSinceStart, totalRecvSinceStart, bpsSentBytes, bpsRecvBytes)
    private static (long totalSent, long totalRecv, double bpsSent, double bpsRecv) SampleNetwork()
    {
        var now = DateTime.UtcNow;
        double elapsed = (now - _prevTime).TotalSeconds;
        if (elapsed <= 0) elapsed = 1e-3;

        long totalSentSinceStart = 0;
        long totalRecvSinceStart = 0;
        double bpsSent = 0, bpsRecv = 0;

        // compute per-NIC deltas and aggregate
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!ShouldIncludeNic(ni)) continue;
            string key = ni.Id;

            long sent = 0, recv = 0;
            try
            {
                var s = ni.GetIPv4Statistics(); // IPv6 not included by API; in practice, Windows increments these for IPv6 too on many drivers
                sent = s.BytesSent;
                recv = s.BytesReceived;
            }
            catch { continue; }

            if (!_nicStart.ContainsKey(key))
                _nicStart[key] = (sent, recv);
            if (!_nicPrev.ContainsKey(key))
                _nicPrev[key] = (sent, recv);

            var (s0, r0) = _nicStart[key];
            var (sp, rp) = _nicPrev[key];

            long sinceStartSent = Math.Max(0, sent - s0);
            long sinceStartRecv = Math.Max(0, recv - r0);

            long deltaSent = Math.Max(0, sent - sp);
            long deltaRecv = Math.Max(0, recv - rp);

            // per-NIC instantaneous B/s
            double nicBpsSent = deltaSent / elapsed;
            double nicBpsRecv = deltaRecv / elapsed;

            // aggregate totals since start (sum of selected NICs)
            totalSentSinceStart += sinceStartSent;
            totalRecvSinceStart += sinceStartRecv;

            if (_nicSumMode)
            {
                bpsSent += nicBpsSent;
                bpsRecv += nicBpsRecv;
            }
            else
            {
                bpsSent = Math.Max(bpsSent, nicBpsSent);
                bpsRecv = Math.Max(bpsRecv, nicBpsRecv);
            }

            _nicPrev[key] = (sent, recv);
        }

        _prevTime = now;
        return (totalSentSinceStart, totalRecvSinceStart, bpsSent, bpsRecv);
    }

    // ===== NIC helpers =====

    private static void ResetNicBaselines()
    {
        _nicStart.Clear();
        _nicPrev.Clear();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (!ShouldIncludeNic(ni)) continue;
            try
            {
                var s = ni.GetIPv4Statistics();
                _nicStart[ni.Id] = (s.BytesSent, s.BytesReceived);
                _nicPrev[ni.Id]  = (s.BytesSent, s.BytesReceived);
            }
            catch { }
        }
        _prevTime = DateTime.UtcNow;
    }

    private static IEnumerable<(string name, string desc, string type, bool up, bool include)> EnumerateNics()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            bool up = ni.OperationalStatus == OperationalStatus.Up;
            bool include = ShouldIncludeNic(ni);
            yield return (ni.Name, ni.Description, ni.NetworkInterfaceType.ToString(), up, include);
        }
    }

    private static bool ShouldIncludeNic(NetworkInterface ni)
    {
        if (ni.OperationalStatus != OperationalStatus.Up) return false;
        if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) return false;

        // quick virtual/tunnel heuristics unless explicitly allowed
        var name = (ni.Name ?? string.Empty);
        var desc = (ni.Description ?? string.Empty);
        if (!_includeVirtual)
        {
            string s = (name + " " + desc).ToLowerInvariant();
            string[] virtualMarkers = {
                "virtual", "vmware", "hyper-v", "vethernet", "virtual switch", "switch extension",
                "docker", "br-", "veth", "tailscale", "wg", "wireguard", "host-only",
                "zerotier", "npcap", "bridge", "loopback", "bluetooth", "wi-fi direct", "wfp", "qos", "ndis", "filter", "miniport", "wan miniport", "virtualbox", "kernel debug", "xbox", "teredo", "ip-https", "6to4", "pppoe", "ikev2", "l2tp", "pptp", "sstp", "network monitor"
            };
            foreach (var m in virtualMarkers)
                if (s.Contains(m)) return false;
        }

        // If user passed explicit NIC filters, require a match on Name or Description
        if (_nicFilters.Length > 0)
        {
            bool match = _nicFilters.Any(f =>
                name.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                desc.Contains(f, StringComparison.OrdinalIgnoreCase));
            return match;
        }

        return true;
    }

    // ===== Process helpers =====

    private static string[] ParseListArg(string[] args, params string[] keys)
    {
        var raw = GetArg(args, keys);
        if (string.IsNullOrWhiteSpace(raw)) return Array.Empty<string>();
        return raw.Split(new[] { ';', ',', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                  .Select(s => s.Trim())
                  .Where(s => s.Length > 0)
                  .ToArray();
    }

    private static bool HasFlag(string[] args, params string[] keys)
        => GetArg(args, keys) == string.Empty || args.Any(a => keys.Any(k => a.Equals(k, StringComparison.OrdinalIgnoreCase)));

    private static string? GetArg(string[] args, params string[] keys)
    {
        if (args == null) return null;
        for (int i = 0; i < args.Length; i++)
        {
            foreach (var k in keys)
            {
                if (args[i].Equals(k, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        return args[i + 1];
                    return string.Empty;
                }
                if (args[i].StartsWith(k + "=", StringComparison.OrdinalIgnoreCase))
                    return args[i].Substring(k.Length + 1);
            }
        }
        return null;
    }

    private static IEnumerable<Process> GetMatchingProcesses(string[] filters)
    {
        var all = Process.GetProcesses();
        if (filters is null || filters.Length == 0) return all;

        return all.Where(p =>
        {
            try
            {
                var n = SafeName(p);
                foreach (var f in filters)
                {
                    if (n.Equals(f, StringComparison.OrdinalIgnoreCase)) return true;
                    if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                        n.AsSpan(0, n.Length - 4).Equals(f.AsSpan(), StringComparison.OrdinalIgnoreCase)) return true;
                    if (n.Contains(f, StringComparison.OrdinalIgnoreCase)) return true;

                    var cmd = TryReadCmdline(p);
                    if (!string.IsNullOrEmpty(cmd) && cmd.IndexOf(f, StringComparison.OrdinalIgnoreCase) >= 0) return true;
                }
                return false;
            }
            catch { return false; }
        }).ToArray();
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName; } catch { return $"pid-{p.Id}"; }
    }

    private static long SafeWorkingSet(Process p)
    {
        try { return p.WorkingSet64; } catch { return 0L; }
    }

    private static void SafeDispose(Process p)
    {
        try { p.Dispose(); } catch { }
    }

    private static (double rdBps, double wrBps) LinuxIoBps(int pid)
    {
        try
        {
            var path = $"/proc/{pid}/io";
            if (!File.Exists(path)) return (0, 0);

            long readBytes = 0, writeBytes = 0;
            foreach (var line in File.ReadLines(path))
            {
                if (line.StartsWith("read_bytes:"))
                {
                    var d = new string(line.Where(char.IsDigit).ToArray());
                    long.TryParse(d, out readBytes);
                }
                else if (line.StartsWith("write_bytes:"))
                {
                    var d = new string(line.Where(char.IsDigit).ToArray());
                    long.TryParse(d, out writeBytes);
                }
            }

            var now = DateTime.UtcNow;
            const string keyPrefix = "pid:";
            string key = keyPrefix + pid;
            if (!_linuxPrevIo.TryGetValue(key, out var prev))
            {
                _linuxPrevIo[key] = (readBytes, writeBytes, now);
                return (0, 0);
            }
            double dt = (now - prev.t).TotalSeconds;
            if (dt <= 0) dt = 1;
            var rd = readBytes - prev.r;
            var wr = writeBytes - prev.w;
            _linuxPrevIo[key] = (readBytes, writeBytes, now);
            return (rd > 0 ? rd / dt : 0, wr > 0 ? wr / dt : 0);
        }
        catch { return (0, 0); }
    }
    private static readonly Dictionary<string, (long r, long w, DateTime t)> _linuxPrevIo = new();

    private static string? TryReadCmdline(Process p)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            try
            {
                var bytes = File.ReadAllBytes($"/proc/{p.Id}/cmdline");
                if (bytes.Length == 0) return null;
                var parts = System.Text.Encoding.UTF8.GetString(bytes).Split('\0', StringSplitOptions.RemoveEmptyEntries);
                return string.Join(' ', parts);
            }
            catch { return null; }
        }
        else
        {
            return null; // could add WMI later
        }
    }

    // ===== Memory & CPU =====

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

                static long ParseKiBLine(string line)
                {
                    var parts = line.Split(':', 2);
                    if (parts.Length < 2) return 0;
                    var digits = new string(parts[1].Where(char.IsDigit).ToArray());
                    return long.TryParse(digits, out var kib) ? kib * 1024 : 0;
                }
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

        var info = GC.GetGCMemoryInfo();
        long approxTotal = info.TotalAvailableMemoryBytes > 0 ? info.TotalAvailableMemoryBytes : 0;
        long approxAvail = approxTotal > 0 ? approxTotal - Process.GetCurrentProcess().WorkingSet64 : 0;
        return (approxTotal, approxAvail);
    }

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
        return Math.Clamp(pct, 0, 100);

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
    }

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
        return Math.Clamp(maxPct, 0, 100);

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

                foreach (var c in counters) _ = c.NextValue(); // prime
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
    private static Task<double> SampleWindowsMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
        => Task.FromResult(fallbackOverall);
    #endif

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
