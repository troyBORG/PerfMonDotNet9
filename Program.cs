
// Program.cs — ONE endpoint (/perf-stats), CSV output only.
// Format:
// cpu_percent, core_percent, mem_total, mem_avail, total_bytes_sent, total_bytes_received, bps_sent, bps_received
//
// Behavior:
// - No args           => returns system-wide CPU, max core, memory, and network (primary NIC).
/* - With --procs "A;B;C"
     => returns CPU% and core% computed from ONLY the matching processes (sum for CPU%, capped 100 for core%).
        Memory and network remain system-wide (per-process network is not reliably available cross-platform
        without privileged OS-specific collectors). */
//
// Endpoint: /perf-stats (CSV). No JSON, no other routes. No NIC debug args.

using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

var filters = ParseProcFilters(args);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args });
builder.WebHost.UseKestrel(opt => opt.Listen(IPAddress.Any, 8082));
var app = builder.Build();

// Network baselines
var nicIds = SelectPrimaryNics();
var nicStart = new Dictionary<string, (long sent, long recv)>();
var nicPrev  = new Dictionary<string, (long sent, long recv)>();
DateTime prevTime = DateTime.UtcNow;

ResetCounters();

// Optional: reset counters
app.MapGet("/reset-counters", ctx =>
{
    ResetCounters();
    return Results.Text("Bandwidth counters reset");
});

// CSV perf endpoint
app.MapGet("/perf-stats", async ctx =>
{
    var sample = TimeSpan.FromSeconds(1);

    double cpuPercent, corePercent;
    if (filters.Length == 0)
    {
        // System mode
        cpuPercent  = await SampleSystemCpuPercentAsync(sample);
        corePercent = await SampleMaxCorePercentAsync(sample, cpuPercent);
    }
    else
    {
        // Filtered mode: sum CPU% of matching processes; "core%" approximated as min(100, sum CPU%)
        (cpuPercent, _) = await SampleFilteredCpuPercentAsync(sample, filters);
        corePercent = Math.Min(100.0, cpuPercent);
    }

    var (memTotal, memAvail) = GetSystemMemoryBytes();

    var (totSent, totRecv, bpsSent, bpsRecv) = SampleNetwork();

    string csv = $"{cpuPercent}, {corePercent}, {memTotal}, {memAvail}, {totSent}, {totRecv}, {bpsSent}, {bpsRecv}";
    return Results.Text(csv);
});

await app.RunAsync();

// ===== Helpers =====

static string[] ParseProcFilters(string[] args)
{
    if (args == null || args.Length == 0) return Array.Empty<string>();
    static string? Get(string[] a, params string[] keys)
    {
        for (int i = 0; i < a.Length; i++)
        {
            foreach (var k in keys)
            {
                if (a[i].Equals(k, StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < a.Length) return a[i + 1];
                    return "";
                }
                if (a[i].StartsWith(k + "=", StringComparison.OrdinalIgnoreCase))
                    return a[i].Substring(k.Length + 1);
            }
        }
        return null;
    }

    var raw = Get(args, "--procs", "-p");
    if (string.IsNullOrWhiteSpace(raw)) return Array.Empty<string>();

    return raw
        .Split(new[] { ';', ',', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(s => s.Trim())
        .Where(s => s.Length > 0)
        .ToArray();
}

IEnumerable<NetworkInterface> GetIncludedNics()
{
    // Choose primary NICs: up, not loopback, with a gateway, and not obviously virtual/tunnel.
    var all = NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

    var primary = all.Where(n =>
    {
        try
        {
            var props = n.GetIPProperties();
            bool hasGw = props.GatewayAddresses.Any(g => g?.Address != null && g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (!hasGw) return false;
        }
        catch { return false; }

        var s = ((n.Name ?? "") + " " + (n.Description ?? "")).ToLowerInvariant();
        string[] bad = {
            "virtual", "vmware", "hyper-v", "vethernet", "switch", "host-only",
            "npcap", "tailscale", "bridge", "bluetooth", "wireguard", "wg ", "zerotier",
            "virtualbox", "pppoe", "teredo", "ip-https", "6to4", "wan miniport",
            "ndis", "filter", "qos", "network monitor", "kernel debug", "xbox"
        };
        foreach (var m in bad) if (s.Contains(m)) return false;
        return true;
    }).ToArray();

    if (primary.Length > 0) return primary;

    // Fallback: any up, non-loopback NIC that isn't obviously virtual.
    return all.Where(n =>
    {
        var s = ((n.Name ?? "") + " " + (n.Description ?? "")).ToLowerInvariant();
        string[] bad = { "virtual", "vmware", "hyper-v", "vethernet", "npcap", "tailscale", "wireguard", "host-only", "virtualbox" };
        foreach (var m in bad) if (s.Contains(m)) return false;
        return true;
    });
}

(string[] nicIds, Func<(long sent, long recv)> snapshot) InitNicSnapshot()
{
    var nics = GetIncludedNics().ToArray();
    var ids = nics.Select(n => n.Id).ToArray();

    (long sent, long recv) Snap()
    {
        long s = 0, r = 0;
        foreach (var ni in nics)
        {
            try
            {
                var st = ni.GetIPv4Statistics();
                s += st.BytesSent;
                r += st.BytesReceived;
            }
            catch { }
        }
        return (s, r);
    }
    return (ids, Snap);
}

void ResetCounters()
{
    (nicIds, var snap) = InitNicSnapshot();
    var now = DateTime.UtcNow;
    var (s, r) = snap();
    nicStart.Clear();
    nicPrev.Clear();
    foreach (var id in nicIds)
    {
        nicStart[id] = (s, r);
        nicPrev[id]  = (s, r);
    }
    prevTime = now;
}

(long totalSent, long totalRecv, double bpsSent, double bpsRecv) SampleNetwork()
{
    (var ids, var snap) = InitNicSnapshot(); // refresh NIC list in case state changed
    var (sNow, rNow) = snap();

    // Store per-call using the first id as key (we treat the aggregated sum as one logical interface)
    string key = ids.FirstOrDefault() ?? "agg";

    if (!nicStart.ContainsKey(key)) nicStart[key] = (sNow, rNow);
    if (!nicPrev.ContainsKey(key))  nicPrev[key]  = (sNow, rNow);

    var (s0, r0) = nicStart[key];
    var (sp, rp) = nicPrev[key];

    var now = DateTime.UtcNow;
    double dt = (now - prevTime).TotalSeconds;
    if (dt <= 0) dt = 1e-3;

    long totalSentSinceStart = Math.Max(0, sNow - s0);
    long totalRecvSinceStart = Math.Max(0, rNow - r0);

    long dS = Math.Max(0, sNow - sp);
    long dR = Math.Max(0, rNow - rp);

    double bpsS = dS / dt;
    double bpsR = dR / dt;

    nicPrev[key] = (sNow, rNow);
    prevTime = now;

    return (totalSentSinceStart, totalRecvSinceStart, bpsS, bpsR);
}

static (long total, long available) GetSystemMemoryBytes()
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
    {
        try
        {
            long total = 0, avail = 0;
            foreach (var line in File.ReadLines("/proc/meminfo"))
            {
                if (line.StartsWith("MemTotal:")) total = ParseKiB(line);
                else if (line.StartsWith("MemAvailable:")) avail = ParseKiB(line);
                if (total > 0 && avail > 0) break;
            }
            return (total, avail);

            static long ParseKiB(string line)
            {
                var parts = line.Split(':', 2);
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
            var m = new MEMORYSTATUSEX();
            if (GlobalMemoryStatusEx(m))
                return ((long)m.ullTotalPhys, (long)m.ullAvailPhys);
        }
        catch { }
    }
    var info = GC.GetGCMemoryInfo();
    long approxTotal = info.TotalAvailableMemoryBytes > 0 ? info.TotalAvailableMemoryBytes : 0;
    long approxAvail = approxTotal > 0 ? approxTotal - Process.GetCurrentProcess().WorkingSet64 : 0;
    return (approxTotal, approxAvail);
}

static async Task<double> SampleSystemCpuPercentAsync(TimeSpan sample)
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

static async Task<double> SampleMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
{
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        return await SampleLinuxMaxCorePercentAsync(sample);
    else
        return await SampleWindowsMaxCorePercentAsync(sample, fallbackOverall);
}

static async Task<(double sumPercent, int processesCount)> SampleFilteredCpuPercentAsync(TimeSpan sample, string[] filters)
{
    var targets = GetMatchingProcesses(filters);
    var t0 = new Dictionary<int, TimeSpan>();

    foreach (var p in targets)
    {
        try { t0[p.Id] = p.TotalProcessorTime; }
        catch { }
        finally { try { p.Dispose(); } catch { } }
    }

    await Task.Delay(sample);

    int logical = Math.Max(1, Environment.ProcessorCount);
    double sum = 0;
    int count = 0;

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
            count++;
        }
        catch { }
        finally { try { p.Dispose(); } catch { } }
    }

    return (sum, count);
}

static IEnumerable<Process> GetMatchingProcesses(string[] filters)
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
                    // Linux: match cmdline substring (dotnet Resonite.dll)
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

// Linux per-core max via /proc/stat
static async Task<double> SampleLinuxMaxCorePercentAsync(TimeSpan sample)
{
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
static async Task<double> SampleWindowsMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
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
static Task<double> SampleWindowsMaxCorePercentAsync(TimeSpan sample, double fallbackOverall)
    => Task.FromResult(fallbackOverall);
#endif

struct CpuLine
{
    public ulong user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    public ulong Total() => user + nice + system + idle + iowait + irq + softirq + steal + guest + guest_nice;
}

// Win memory P/Invoke
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
class MEMORYSTATUSEX
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
static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);
