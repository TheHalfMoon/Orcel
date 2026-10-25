// Orcel Desktop Foundation — read-only Windows preview.
// This preview never sends screenshots or text to a model, network, or remote device.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;


namespace Orcel.DesktopPreview
{
    internal enum SafeCommand { Help, Status, Version, Doctor, Devices, Files, Tasks, Unsupported }

    internal static class CommandRouter
    {
        internal static SafeCommand Classify(string input)
        {
            string value = (input ?? "").Trim().ToLowerInvariant();
            if (value == "help" || value == "?") return SafeCommand.Help;
            if (value == "status") return SafeCommand.Status;
            if (value == "version") return SafeCommand.Version;
            if (value == "doctor") return SafeCommand.Doctor;
            if (value == "devices") return SafeCommand.Devices;
            if (value == "files") return SafeCommand.Files;
            if (value == "tasks") return SafeCommand.Tasks;
            return SafeCommand.Unsupported;
        }

        internal static bool CanInvokeInstalledHost(SafeCommand command)
        {
            return command == SafeCommand.Status || command == SafeCommand.Version || command == SafeCommand.Doctor;
        }

        /// The only arguments ever passed to the runtime: fixed, read-only queries.
        internal static string[] CliArguments(SafeCommand command)
        {
            if (command == SafeCommand.Status) return new[] { "status", "--json" };
            if (command == SafeCommand.Version) return new[] { "version", "--json" };
            if (command == SafeCommand.Doctor) return new[] { "doctor", "--json" };
            return null;
        }
    }

    /// Result of one bounded child-process run.
    internal sealed class CliResult
    {
        internal int ExitCode = -1;
        internal string Stdout = "";
        internal bool TimedOut;
        internal bool Truncated;
        internal bool FailedToStart;
    }

    internal static class BoundedProcess
    {
        internal const int MaxOutputChars = 256 * 1024;

        /// Runs a child with both streams drained concurrently (so a full pipe can
        /// never deadlock it) and a bounded amount of output kept. The child is
        /// placed in a kill-on-close Job Object: on timeout the job is terminated,
        /// and any descendants still alive when the query ends are killed with it.
        /// Processes the child starts before it joins the job (a few
        /// milliseconds after start) are not covered; if no job can be created,
        /// only the direct child is killed on timeout.
        internal static CliResult Run(string fileName, string[] arguments, int timeoutMs, string localAppData)
        {
            CliResult result = new CliResult();
            using (Process process = new Process())
            {
                process.StartInfo = new ProcessStartInfo {
                    FileName = fileName,
                    Arguments = string.Join(" ", arguments.Select(Quote).ToArray()),
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = true,
                    WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
                };
                if (localAppData != null) process.StartInfo.EnvironmentVariables["LOCALAPPDATA"] = localAppData;
                try { process.Start(); }
                catch (Exception) { result.FailedToStart = true; return result; }
                // The child and everything it starts after this point are killed
                // together on timeout (and when the job handle closes).
                JobObject job = JobObject.TryCreateFor(process);
                try { process.StandardInput.Close(); } catch (Exception) { }
                bool stdoutTruncated = false;
                Task<string> stdout = Task.Factory.StartNew(() => ReadBounded(process.StandardOutput, out stdoutTruncated), TaskCreationOptions.LongRunning);
                bool ignored;
                Task<string> stderr = Task.Factory.StartNew(() => ReadBounded(process.StandardError, out ignored), TaskCreationOptions.LongRunning);
                try
                {
                    if (!process.WaitForExit(timeoutMs))
                    {
                        result.TimedOut = true;
                        if (job == null || !job.Terminate())
                        {
                            try { process.Kill(); } catch (Exception) { }
                        }
                        process.WaitForExit(2000);
                    }
                    try { Task.WaitAll(new Task[] { stdout, stderr }, 2000); } catch (AggregateException) { }
                    // A faulted or unfinished read yields no output, never an exception.
                    result.Stdout = stdout.Status == TaskStatus.RanToCompletion ? stdout.Result : "";
                    result.Truncated = stdoutTruncated;
                    if (!result.TimedOut && process.HasExited) result.ExitCode = process.ExitCode;
                }
                finally
                {
                    if (job != null) job.Dispose();
                }
            }
            return result;
        }

        private static string Quote(string argument)
        {
            return argument.IndexOfAny(new[] { ' ', '"', '\t' }) < 0 ? argument : "\"" + argument.Replace("\"", "\\\"") + "\"";
        }

        private static string ReadBounded(StreamReader reader, out bool truncated)
        {
            truncated = false;
            StringBuilder kept = new StringBuilder();
            char[] buffer = new char[4096];
            int read;
            // Keep reading after the limit so the child never blocks on a full pipe.
            while ((read = reader.Read(buffer, 0, buffer.Length)) > 0)
            {
                int room = MaxOutputChars - kept.Length;
                if (room > 0) kept.Append(buffer, 0, Math.Min(room, read));
                if (read > room) truncated = true;
            }
            return kept.ToString();
        }

    }

    /// A Windows Job Object with kill-on-close, so a timed-out query cannot
    /// leave its own child processes behind and cannot affect any other process.
    internal sealed class JobObject : IDisposable
    {
        private IntPtr handle;

        internal static JobObject TryCreateFor(Process process)
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) return null;
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            bool ok = SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
            try { ok = ok && AssignProcessToJobObject(job, process.Handle); }
            catch (Exception) { ok = false; }
            if (!ok) { CloseHandle(job); return null; }
            return new JobObject { handle = job };
        }

        internal bool Terminate()
        {
            return handle != IntPtr.Zero && TerminateJobObject(handle, 1);
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }

        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
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
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
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
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }

    internal enum RuntimeAvailability { NotInstalled, Unresponsive, Incompatible, Installed }

    /// What the app truthfully knows about the local Orcel runtime.
    internal sealed class RuntimeStatus
    {
        internal RuntimeAvailability Availability;
        internal string Version;
        internal string State;
        internal string Detail;
        internal int? Workspaces;

        internal string Headline()
        {
            switch (Availability)
            {
                case RuntimeAvailability.NotInstalled: return "Not installed";
                case RuntimeAvailability.Unresponsive: return "Installed • not responding";
                case RuntimeAvailability.Incompatible: return "Installed • incompatible response";
                default: return "Orcel runtime " + Version + " • " + Describe(State);
            }
        }

        internal static string Describe(string state)
        {
            if (state == "running") return "running";
            if (state == "degraded") return "degraded";
            if (state == "not_running") return "not running";
            return "state unknown";
        }
    }

    internal static class LocalHost
    {
        /// Same resolution as the runtime itself: %LOCALAPPDATA%, then the
        /// known folder. Never PATH, never a model- or user-provided path.
        internal static string LocalAppData()
        {
            string fromEnvironment = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (IsDriveQualified(fromEnvironment)) return fromEnvironment;
            return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        /// `C:\...` only: no UNC share (`\\host\share`), no drive-relative path.
        internal static bool IsDriveQualified(string path)
        {
            return !string.IsNullOrEmpty(path) && path.Length >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
                && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
        }

        internal static string PathToCompatCli()
        {
            return Path.Combine(LocalAppData(), "Orcel", "bin", "orcel.exe");
        }

        internal static bool IsInstalled()
        {
            return File.Exists(PathToCompatCli());
        }

        internal static CliResult Query(SafeCommand command, int timeoutMs)
        {
            string[] arguments = CommandRouter.CliArguments(command);
            if (arguments == null) throw new ArgumentException("not a read-only runtime query");
            return BoundedProcess.Run(PathToCompatCli(), arguments, timeoutMs, LocalAppData());
        }

        internal static RuntimeStatus ReadStatus(int timeoutMs)
        {
            if (!IsInstalled()) return new RuntimeStatus { Availability = RuntimeAvailability.NotInstalled };
            CliResult result = Query(SafeCommand.Status, timeoutMs);
            return Interpret.Status(result);
        }
    }

    /// SG-000127 slice 5 (timeline): a read-only client of orceld's local app
    /// API (`orcel-app-api/1`, ORCEL_APP_API_1.md). It sends only `task.list`
    /// and `task.get`, one request per connection, to this user's pipe
    /// `\\.\pipe\orcel-<user SID>-app` as an identification-only client; it
    /// never sends anything that submits, approves, stops or writes. Frames
    /// are bounded to the protocol's 65,536 bytes and every call has a
    /// timeout. Task titles and paths come from the planner and the
    /// workspace: they are shown as data, never acted on.
    internal static class AppApi
    {
        internal const string Protocol = "orcel-app-api/1";
        internal const int MaxFrameBytes = 65536;
        internal const int TimeoutMs = 4000;
        /// The only methods this client sends; both are read-only in orceld.
        internal static readonly string[] Methods = { "task.list", "task.get" };

        internal static string PipeName()
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            string suffix = InstanceSuffix(Environment.GetEnvironmentVariable("ORCEL_APP_API_INSTANCE"));
            return "orcel-" + sid + "-app" + (suffix == null ? "" : "-" + suffix);
        }

        /// The protocol's test suffix: 1-32 of a-z, 0-9 and '-'. Anything
        /// else is ignored, never passed into a pipe name.
        internal static string InstanceSuffix(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 32) return null;
            foreach (char c in value)
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return null;
            return value;
        }

        internal static string RequestFrame(string method, string taskId)
        {
            if (Array.IndexOf(Methods, method) < 0) throw new ArgumentException("not a read-only app API method");
            Dictionary<string, object> request = new Dictionary<string, object>();
            request["v"] = Protocol;
            request["id"] = "desktop";
            request["method"] = method;
            Dictionary<string, object> parameters = new Dictionary<string, object>();
            if (method == "task.get") parameters["task_id"] = taskId ?? "";
            request["params"] = parameters;
            return new JavaScriptSerializer().Serialize(request) + "\n";
        }

        /// One request on its own connection; null when orceld does not answer.
        internal static Dictionary<string, object> Call(string method, string taskId)
        {
            string frame = RequestFrame(method, taskId);
            Task<string> exchange = Task.Factory.StartNew(delegate {
                using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", PipeName(), PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Identification))
                {
                    pipe.Connect(TimeoutMs);
                    byte[] bytes = Encoding.UTF8.GetBytes(frame);
                    pipe.Write(bytes, 0, bytes.Length);
                    pipe.Flush();
                    return ReadFrame(pipe);
                }
            }, TaskCreationOptions.LongRunning);
            try
            {
                if (!exchange.Wait(TimeoutMs + 1000)) return null;
                return ParseReply(exchange.Result);
            }
            catch (Exception) { return null; }
        }

        private static string ReadFrame(Stream stream)
        {
            MemoryStream buffer = new MemoryStream();
            int b;
            while ((b = stream.ReadByte()) >= 0)
            {
                if (b == '\n') return Encoding.UTF8.GetString(buffer.ToArray());
                if (buffer.Length >= MaxFrameBytes) return null;
                buffer.WriteByte((byte)b);
            }
            return null;
        }

        /// The `result` of an ok frame of this protocol, else null.
        internal static Dictionary<string, object> ParseReply(string line)
        {
            if (line == null) return null;
            try
            {
                Dictionary<string, object> reply = new JavaScriptSerializer { MaxJsonLength = MaxFrameBytes }.DeserializeObject(line) as Dictionary<string, object>;
                object v, ok, result;
                if (reply == null || !reply.TryGetValue("v", out v) || !Protocol.Equals(v)) return null;
                if (!reply.TryGetValue("ok", out ok) || !true.Equals(ok)) return null;
                if (!reply.TryGetValue("result", out result)) return null;
                return result as Dictionary<string, object>;
            }
            catch (Exception) { return null; }
        }
    }

    /// The task timeline as text: what orceld recorded, nothing inferred.
    internal static class Timeline
    {
        internal const int MaxShownTasks = 5;
        internal const int MaxShownSteps = 8;
        private const int MaxTitleChars = 120;

        private static string Field(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : null;
        }

        private static string Shown(string value)
        {
            if (value == null) return "(none)";
            StringBuilder text = new StringBuilder();
            foreach (char c in value)
            {
                if (text.Length >= MaxTitleChars) { text.Append("…"); break; }
                text.Append(char.IsControl(c) ? ' ' : c);
            }
            return text.ToString();
        }

        internal static string Describe(string state)
        {
            switch (state)
            {
                case "observed": return "sources read";
                case "proposed": return "report proposed, waiting for approval";
                case "approval_denied": return "approval denied";
                case "committing": return "writing the approved report";
                case "verified": return "verified by the independent checker";
                case "verification_failed": return "verification FAILED";
                case "stale": return "stale (a source or the folder changed)";
                case "failed": return "failed";
                default: return "unknown state";
            }
        }

        internal static List<string> NewestIds(Dictionary<string, object> list)
        {
            List<string> ids = new List<string>();
            object tasks;
            if (list == null || !list.TryGetValue("tasks", out tasks) || !(tasks is IEnumerable)) return ids;
            foreach (object task in (IEnumerable)tasks)
            {
                string id = Field(task as Dictionary<string, object>, "task_id");
                if (id != null && ids.Count < MaxShownTasks) ids.Add(id);
            }
            return ids;
        }

        internal static string Text(Dictionary<string, object> list, IList<Dictionary<string, object>> tasks)
        {
            if (list == null)
                return "Task timeline unavailable: orceld's local app API did not answer (the runtime may not be running). Nothing was changed.";
            List<string> ids = NewestIds(list);
            if (ids.Count == 0) return "No report tasks in this orceld run. Tasks are started by a connected local MCP client; this app only shows them.";
            StringBuilder text = new StringBuilder();
            text.Append("Report tasks in this orceld run (newest first; titles come from the planner and are not verified):");
            for (int i = 0; i < ids.Count; i++)
            {
                Dictionary<string, object> task = i < tasks.Count ? tasks[i] : null;
                if (task == null) { text.Append("\n• " + ids[i] + ": details unavailable"); continue; }
                text.Append("\n• \"" + Shown(Field(task, "title")) + "\": " + Describe(Field(task, "state")));
                object report;
                if (task.TryGetValue("report", out report) && report is Dictionary<string, object>)
                    text.Append(" → " + Shown(Field((Dictionary<string, object>)report, "destination")));
                object steps;
                if (task.TryGetValue("steps", out steps) && steps is IEnumerable)
                {
                    List<string> outcomes = new List<string>();
                    foreach (object step in (IEnumerable)steps)
                    {
                        Dictionary<string, object> map = step as Dictionary<string, object>;
                        outcomes.Add(Shown(Field(map, "kind")) + " " + Shown(Field(map, "outcome")));
                    }
                    if (outcomes.Count > MaxShownSteps) outcomes = outcomes.Skip(outcomes.Count - MaxShownSteps).ToList();
                    if (outcomes.Count > 0) text.Append("\n   steps: " + string.Join(" · ", outcomes));
                }
            }
            text.Append("\nThis app reads tasks only; it cannot start, approve or stop them.");
            return text.ToString();
        }

        internal static string Read()
        {
            Dictionary<string, object> list = AppApi.Call("task.list", null);
            List<Dictionary<string, object>> details = new List<Dictionary<string, object>>();
            foreach (string id in NewestIds(list)) details.Add(AppApi.Call("task.get", id));
            return Text(list, details);
        }
    }

    /// Turns the runtime's JSON into truthful, bounded user-facing text.
    internal static class Interpret
    {
        private static Dictionary<string, object> Parse(string json)
        {
            try
            {
                JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = BoundedProcess.MaxOutputChars };
                return serializer.DeserializeObject(json) as Dictionary<string, object>;
            }
            catch (Exception) { return null; }
        }

        private static string Text(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : null;
        }

        internal static RuntimeStatus Status(CliResult result)
        {
            if (result.FailedToStart || result.TimedOut) return new RuntimeStatus { Availability = RuntimeAvailability.Unresponsive };
            Dictionary<string, object> json = Parse(result.Stdout);
            object runtime = null;
            if (json == null || result.ExitCode != 0 || !(json.ContainsKey("ok") && true.Equals(json["ok"]))
                || !json.TryGetValue("runtime", out runtime) || !(runtime is Dictionary<string, object>))
                return new RuntimeStatus { Availability = RuntimeAvailability.Incompatible };
            Dictionary<string, object> runtimeMap = (Dictionary<string, object>)runtime;
            string version = Text(json, "installed");
            if (version == null) return new RuntimeStatus { Availability = RuntimeAvailability.NotInstalled };
            int workspaces;
            return new RuntimeStatus {
                Availability = RuntimeAvailability.Installed,
                Version = version,
                State = Text(runtimeMap, "state"),
                Detail = Text(runtimeMap, "detail"),
                Workspaces = int.TryParse(Text(json, "workspaces"), out workspaces) ? (int?)workspaces : null
            };
        }

        internal static string StatusMessage(RuntimeStatus status)
        {
            if (status.Availability == RuntimeAvailability.NotInstalled)
                return "The Orcel runtime is not installed for this Windows user. No operation was attempted.";
            if (status.Availability == RuntimeAvailability.Unresponsive)
                return "The Orcel runtime did not answer a read-only status query in time. No action was performed.";
            if (status.Availability == RuntimeAvailability.Incompatible)
                return "The installed Orcel runtime returned a response this preview does not understand. No action was performed.";
            StringBuilder text = new StringBuilder();
            text.Append("Orcel runtime ").Append(status.Version).Append(" is installed and ").Append(RuntimeStatus.Describe(status.State));
            if (!string.IsNullOrEmpty(status.Detail)) text.Append(" (").Append(status.Detail).Append(")");
            text.Append(".");
            if (status.Workspaces.HasValue) text.Append(" Workspaces configured: ").Append(status.Workspaces.Value).Append(".");
            return text.ToString();
        }

        internal static string VersionMessage(CliResult result)
        {
            if (result.FailedToStart || result.TimedOut) return "The Orcel runtime did not answer a read-only version query in time.";
            Dictionary<string, object> json = result.ExitCode == 0 ? Parse(result.Stdout) : null;
            string cli = Text(json, "cli");
            if (json == null || cli == null) return "The installed Orcel runtime returned a version response this preview does not understand.";
            string installed = Text(json, "installed");
            return "Orcel CLI " + cli + "; installed release " + (installed ?? "none") + ".";
        }

        /// Doctor exits non-zero when any check fails; its JSON is still the report.
        internal static string DoctorMessage(CliResult result)
        {
            if (result.FailedToStart || result.TimedOut) return "The Orcel runtime did not finish its read-only health check in time.";
            Dictionary<string, object> json = Parse(result.Stdout);
            object doctor;
            object checks;
            if (json == null || !json.TryGetValue("doctor", out doctor) || !(doctor is Dictionary<string, object>)
                || !((Dictionary<string, object>)doctor).TryGetValue("checks", out checks) || !(checks is IEnumerable))
                return "The installed Orcel runtime returned a health report this preview does not understand.";
            int pass = 0, warn = 0, fail = 0, other = 0;
            List<string> problems = new List<string>();
            foreach (object item in (IEnumerable)checks)
            {
                Dictionary<string, object> check = item as Dictionary<string, object>;
                string state = Text(check, "status");
                if (state == "pass") pass++;
                else if (state == "warn") { warn++; problems.Add("WARN " + Text(check, "name") + ": " + Text(check, "detail")); }
                else if (state == "fail") { fail++; problems.Add("FAIL " + Text(check, "name") + ": " + Text(check, "detail")); }
                else other++;
            }
            StringBuilder text = new StringBuilder();
            text.Append("Health check: ").Append(pass).Append(" passed, ").Append(warn).Append(" warnings, ").Append(fail).Append(" failed");
            if (other > 0) text.Append(", ").Append(other).Append(" unknown");
            text.Append(".");
            foreach (string problem in problems.Take(8)) text.Append("\n").Append(problem);
            if (problems.Count > 8) text.Append("\n…").Append(problems.Count - 8).Append(" more");
            return text.ToString();
        }
    }

    internal static class FolderPreview
    {
        internal const int MaxEntries = 12;

        /// Lists at most MaxEntries names without materializing the directory.
        internal static string List(string folder, CancellationToken cancel)
        {
            return List(Directory.EnumerateFileSystemEntries(folder), cancel);
        }

        internal static string List(IEnumerable<string> entries, CancellationToken cancel)
        {
            List<string> names = new List<string>();
            bool more = false;
            foreach (string entry in entries)
            {
                cancel.ThrowIfCancellationRequested();
                if (names.Count == MaxEntries) { more = true; break; }
                names.Add(Path.GetFileName(entry));
            }
            string summary = names.Count == 0 ? "(empty)" : string.Join("\n", names.ToArray());
            return "Local folder preview (up to " + MaxEntries + " entries" + (more ? "; more not shown" : "") + "):\n" + summary + "\nNo files were modified or uploaded.";
        }

        /// Gives up waiting after `limit` even if the file system never returns
        /// (for example a stalled network share); the abandoned enumeration is
        /// cancelled and its result ignored.
        internal static Task<string> ListWithin(string folder, TimeSpan limit)
        {
            return ListWithin(token => List(folder, token), limit);
        }

        internal static async Task<string> ListWithin(Func<CancellationToken, string> list, TimeSpan limit)
        {
            CancellationTokenSource cancel = new CancellationTokenSource();
            // A dedicated thread: a hung enumeration must not hold a pool thread.
            Task<string> work = Task.Factory.StartNew(() => list(cancel.Token), cancel.Token,
                TaskCreationOptions.LongRunning, TaskScheduler.Default);
            Task finished = await Task.WhenAny(work, Task.Delay(limit));
            if (finished != work)
            {
                cancel.Cancel();
                // Observe the abandoned task's outcome so it can never surface later.
                Task observed = work.ContinueWith(t => { var ignored = t.Exception; cancel.Dispose(); });
                return "Listing this folder took too long, so Orcel stopped waiting for it. No changes were made.";
            }
            cancel.Dispose();
            try { return await work; }
            catch (Exception) { return "Unable to list this folder. No changes were made."; }
        }
    }

    internal static class Colors
    {
        internal static Brush Ink = Hex("#E9EDFA");
        internal static Brush Muted = Hex("#9BA7C5");
        internal static Brush Background = Hex("#090D19");
        internal static Brush Sidebar = Hex("#111729");
        internal static Brush Surface = Hex("#161E34");
        internal static Brush Border = Hex("#29334C");
        internal static Brush Accent = Hex("#9A8CF5");
        internal static Brush Safe = Hex("#73D6BD");
        internal static Brush Bubble = Hex("#222F4D");
        internal static Brush Hex(string value)
        {
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        }
    }

    internal sealed class MainWindow : Window
    {
        private const int QueryTimeoutMs = 8000;
        // Doctor starts the daemon for an IPC probe and takes about 8 s on a typical machine.
        private const int DoctorTimeoutMs = 30000;
        private readonly StackPanel transcript = new StackPanel();
        private readonly TextBox commandBox = new TextBox();
        private readonly TextBlock hostState = new TextBlock();
        private readonly TextBlock deviceState = new TextBlock();
        private readonly ScrollViewer conversation = new ScrollViewer();
        private bool refreshing;
        private int messages;

        internal MainWindow()
        {
            Title = "Orcel — Desktop Foundation";
            Width = 1060;
            Height = 700;
            MinWidth = 720;
            MinHeight = 520;
            Background = Colors.Background;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            FontFamily = new System.Windows.Media.FontFamily("Segoe UI");
            AutomationProperties.SetAutomationId(this, "OrcelMainWindow");
            Content = Layout();
            Loaded += delegate { RefreshHost(); commandBox.Focus(); };
        }

        private static TextBlock Text(string value, double size, Brush brush, bool bold)
        {
            return new TextBlock {
                Text = value, FontSize = size, Foreground = brush,
                FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal,
                TextWrapping = TextWrapping.Wrap
            };
        }

        private static Border Card(UIElement child, Brush background, Thickness padding)
        {
            return new Border {
                Background = background, BorderBrush = Colors.Border, BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14), Padding = padding, Child = child
            };
        }

        private static System.Windows.Controls.Button ActionButton(string title, bool enabled, string automationId)
        {
            System.Windows.Controls.Button button = new System.Windows.Controls.Button {
                Content = title, IsEnabled = enabled,
                Background = enabled ? Colors.Accent : Colors.Surface,
                Foreground = enabled ? Colors.Background : Colors.Muted,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(15, 9, 15, 9),
                FontSize = 12, FontWeight = FontWeights.SemiBold,
                Cursor = enabled ? System.Windows.Input.Cursors.Hand : System.Windows.Input.Cursors.Arrow,
                Margin = new Thickness(0, 0, 0, 10)
            };
            AutomationProperties.SetAutomationId(button, automationId);
            AutomationProperties.SetName(button, title);
            return button;
        }

        private UIElement Layout()
        {
            Grid root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(60) });
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            Border header = new Border {
                Background = Colors.Background, BorderBrush = Colors.Border,
                BorderThickness = new Thickness(0, 0, 0, 1)
            };
            Grid.SetRow(header, 0);
            Grid.SetColumnSpan(header, 2);
            Grid headerContent = new Grid { Margin = new Thickness(22, 0, 22, 0) };
            headerContent.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerContent.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            StackPanel logo = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            logo.Children.Add(Text("✦", 22, Colors.Accent, true));
            TextBlock logoText = Text("  Orcel", 20, Colors.Ink, true);
            logoText.VerticalAlignment = VerticalAlignment.Center;
            logo.Children.Add(logoText);
            headerContent.Children.Add(logo);
            TextBlock stage = Text("DESKTOP FOUNDATION  •  READ-ONLY", 11, Colors.Safe, true);
            stage.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(stage, 1);
            headerContent.Children.Add(stage);
            header.Child = headerContent;
            root.Children.Add(header);

            Grid center = new Grid { Margin = new Thickness(18, 18, 10, 16) };
            center.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            center.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            center.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(center, 1); Grid.SetColumn(center, 0);
            StackPanel headline = new StackPanel { Margin = new Thickness(6, 0, 6, 14) };
            headline.Children.Add(Text("What can I help you with?", 23, Colors.Ink, true));
            TextBlock sub = Text("Read-only foundation: it reports the real local runtime and never executes free text. Orcel AI and remote actions are not connected.", 12, Colors.Muted, false);
            sub.Margin = new Thickness(0, 6, 0, 0);
            headline.Children.Add(sub);
            center.Children.Add(headline);

            conversation.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            conversation.Content = transcript;
            AutomationProperties.SetAutomationId(conversation, "Transcript");
            AutomationProperties.SetName(conversation, "Conversation transcript");
            Border transcriptCard = Card(conversation, Colors.Sidebar, new Thickness(14));
            Grid.SetRow(transcriptCard, 1);
            center.Children.Add(transcriptCard);
            AddMessage(false, "Welcome to Orcel. Type help, status, version, doctor, devices, or files. Other requests are not executed or sent anywhere.");

            Grid composer = new Grid { Margin = new Thickness(0, 12, 0, 0) };
            composer.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            composer.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            commandBox.Background = Colors.Surface;
            commandBox.Foreground = Colors.Ink;
            commandBox.CaretBrush = Colors.Ink;
            commandBox.BorderBrush = Colors.Border;
            commandBox.BorderThickness = new Thickness(1);
            commandBox.FontSize = 14;
            commandBox.Padding = new Thickness(14, 12, 14, 12);
            commandBox.MaxLength = 1024;
            commandBox.ToolTip = "Read-only commands: help, status, version, doctor, devices, files";
            AutomationProperties.SetAutomationId(commandBox, "CommandBox");
            AutomationProperties.SetName(commandBox, "Command");
            AutomationProperties.SetHelpText(commandBox, "Type a read-only command and press Enter");
            commandBox.KeyDown += delegate(object sender, System.Windows.Input.KeyEventArgs e) {
                if (e.Key == Key.Enter) { e.Handled = true; Send(); }
            };
            composer.Children.Add(commandBox);
            System.Windows.Controls.Button send = ActionButton("Send", true, "SendButton");
            send.Margin = new Thickness(10, 0, 0, 0);
            send.MinWidth = 90;
            send.Click += delegate { Send(); };
            Grid.SetColumn(send, 1);
            composer.Children.Add(send);
            Grid.SetRow(composer, 2);
            center.Children.Add(composer);
            root.Children.Add(center);

            StackPanel right = new StackPanel { Margin = new Thickness(8, 18, 18, 16) };
            Grid.SetRow(right, 1); Grid.SetColumn(right, 1);
            TextBlock deviceTitle = Text("This computer", 18, Colors.Ink, true);
            deviceTitle.Margin = new Thickness(0, 0, 0, 12);
            right.Children.Add(deviceTitle);
            StackPanel host = new StackPanel();
            host.Children.Add(Text(Environment.MachineName, 15, Colors.Ink, true));
            deviceState.Text = "Checking runtime";
            deviceState.FontSize = 12; deviceState.Foreground = Colors.Muted;
            deviceState.Margin = new Thickness(0, 6, 0, 0);
            AutomationProperties.SetAutomationId(deviceState, "DeviceState");
            host.Children.Add(deviceState);
            Border deviceCard = Card(host, Colors.Sidebar, new Thickness(16));
            deviceCard.Margin = new Thickness(0, 0, 0, 14);
            right.Children.Add(deviceCard);
            StackPanel runtime = new StackPanel();
            runtime.Children.Add(Text("LOCAL RUNTIME", 10, Colors.Muted, true));
            hostState.Text = "Checking...";
            hostState.TextWrapping = TextWrapping.Wrap;
            hostState.Margin = new Thickness(0, 8, 0, 14);
            hostState.Foreground = Colors.Ink;
            AutomationProperties.SetAutomationId(hostState, "RuntimeState");
            runtime.Children.Add(hostState);
            System.Windows.Controls.Button refresh = ActionButton("Refresh status", true, "RefreshButton");
            refresh.Margin = new Thickness(0);
            refresh.Click += delegate { RefreshHost(); };
            runtime.Children.Add(refresh);
            Border runtimeCard = Card(runtime, Colors.Sidebar, new Thickness(16));
            runtimeCard.Margin = new Thickness(0, 0, 0, 14);
            right.Children.Add(runtimeCard);
            right.Children.Add(Text("ORCEL AI", 10, Colors.Muted, true));
            TextBlock ai = Text("Hala One + Reliance: not connected in this preview.", 12, Colors.Muted, false);
            ai.Margin = new Thickness(0, 8, 0, 14);
            right.Children.Add(ai);
            right.Children.Add(Text("SHELL AND PROCESSES", 10, Colors.Muted, true));
            TextBlock shell = Text("Unavailable: shell and process sessions are not armed in this build.", 12, Colors.Muted, false);
            shell.Margin = new Thickness(0, 8, 0, 14);
            AutomationProperties.SetAutomationId(shell, "ShellState");
            right.Children.Add(shell);
            right.Children.Add(Text("OTHER COMPUTERS", 10, Colors.Muted, true));
            TextBlock pair = Text("No paired devices are shown because pairing is not integrated in this preview.", 12, Colors.Muted, false);
            pair.Margin = new Thickness(0, 8, 0, 10);
            right.Children.Add(pair);
            root.Children.Add(right);
            return root;
        }

        internal void ReportInternalError()
        {
            AddMessage(false, "An internal error occurred in this preview. No action was performed.");
        }

        private void AddMessage(bool fromUser, string message)
        {
            messages++;
            StackPanel item = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            item.HorizontalAlignment = fromUser ? HorizontalAlignment.Right : HorizontalAlignment.Left;
            TextBlock who = Text(fromUser ? "YOU" : "ORCEL · LOCAL", 10, Colors.Muted, true);
            who.Margin = new Thickness(4, 0, 4, 5);
            item.Children.Add(who);
            TextBlock body = Text(message, 13, Colors.Ink, false);
            AutomationProperties.SetAutomationId(body, "Message" + messages);
            Border bubble = Card(body, fromUser ? Colors.Bubble : Colors.Surface, new Thickness(13, 10, 13, 10));
            bubble.MaxWidth = 560;
            item.Children.Add(bubble);
            transcript.Children.Add(item);
            conversation.ScrollToEnd();
        }

        private void Send()
        {
            string value = commandBox.Text.Trim();
            if (value.Length == 0) return;
            commandBox.Clear();
            AddMessage(true, value);
            SafeCommand kind = CommandRouter.Classify(value);
            if (kind == SafeCommand.Help)
                AddMessage(false, "Available: status, version, doctor, devices, files, tasks, help. These operations are read-only. AI chat, voice, pairing, and execution are not connected.");
            else if (kind == SafeCommand.Devices)
                AddMessage(false, "Local computer: " + Environment.MachineName + ". Orcel runtime: " + (LocalHost.IsInstalled() ? "present (type status for its state)" : "not installed") + ". Remote devices: none (pairing is not integrated in this preview).");
            else if (kind == SafeCommand.Files)
                InspectFolder();
            else if (kind == SafeCommand.Tasks)
                ShowTasks();
            else if (CommandRouter.CanInvokeInstalledHost(kind))
                QueryHost(kind);
            else
                AddMessage(false, "Not executed. Orcel AI is not connected. Unknown messages are never treated as shell, web, or computer actions.");
        }

        private async void QueryHost(SafeCommand command)
        {
            if (!LocalHost.IsInstalled())
            {
                AddMessage(false, Interpret.StatusMessage(new RuntimeStatus { Availability = RuntimeAvailability.NotInstalled }));
                return;
            }
            AddMessage(false, "Reading local runtime " + CommandRouter.CliArguments(command)[0] + "...");
            try
            {
                if (command == SafeCommand.Status)
                {
                    RuntimeStatus status = await Task.Run(delegate { return LocalHost.ReadStatus(QueryTimeoutMs); });
                    ShowRuntime(status);
                    AddMessage(false, Interpret.StatusMessage(status));
                    return;
                }
                string response = await Task.Run(delegate {
                    CliResult result = LocalHost.Query(command, command == SafeCommand.Doctor ? DoctorTimeoutMs : QueryTimeoutMs);
                    return command == SafeCommand.Version ? Interpret.VersionMessage(result) : Interpret.DoctorMessage(result);
                });
                AddMessage(false, response);
            }
            catch (Exception)
            {
                AddMessage(false, "The read-only runtime query failed unexpectedly. No action was performed.");
            }
        }

        private void ShowRuntime(RuntimeStatus status)
        {
            hostState.Text = status.Headline();
            deviceState.Text = status.Availability == RuntimeAvailability.NotInstalled
                ? "This PC • Orcel runtime missing"
                : "This PC • " + status.Headline();
        }

        private async void RefreshHost()
        {
            if (refreshing) return;
            refreshing = true;
            hostState.Text = "Checking...";
            deviceState.Text = "Reading local runtime";
            try
            {
                ShowRuntime(await Task.Run(delegate { return LocalHost.ReadStatus(QueryTimeoutMs); }));
            }
            catch (Exception)
            {
                hostState.Text = "Status unavailable";
                deviceState.Text = "This PC • runtime status could not be read";
            }
            finally
            {
                refreshing = false;
            }
        }

        private async void ShowTasks()
        {
            AddMessage(false, "Reading report tasks from the local runtime...");
            try { AddMessage(false, await Task.Run(delegate { return Timeline.Read(); })); }
            catch (Exception) { AddMessage(false, "The read-only task query failed unexpectedly. No action was performed."); }
        }

        private async void InspectFolder()
        {
            string folder;
            using (System.Windows.Forms.FolderBrowserDialog dialog = new System.Windows.Forms.FolderBrowserDialog())
            {
                dialog.Description = "Choose a folder to list locally (read only)";
                if (dialog.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
                folder = dialog.SelectedPath;
            }
            AddMessage(false, "Listing the selected folder...");
            AddMessage(false, await FolderPreview.ListWithin(folder, TimeSpan.FromSeconds(10)));
        }
    }

    internal static class Program
    {
        private static int SelfTest()
        {
            List<string> failures = new List<string>();
            Action<bool, string> expect = (ok, name) => { if (!ok) failures.Add(name); };
            expect(CommandRouter.Classify("status") == SafeCommand.Status, "status routes");
            expect(CommandRouter.Classify(" Doctor ") == SafeCommand.Doctor, "doctor routes");
            expect(CommandRouter.Classify("rm -rf /") == SafeCommand.Unsupported, "shell text rejected");
            expect(CommandRouter.Classify("status; calc.exe") == SafeCommand.Unsupported, "chained text rejected");
            expect(CommandRouter.CliArguments(SafeCommand.Files) == null, "files never reaches the runtime");
            expect(CommandRouter.Classify(" Tasks ") == SafeCommand.Tasks, "tasks routes");
            expect(CommandRouter.CliArguments(SafeCommand.Tasks) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Tasks), "tasks never runs the CLI");
            expect(AppApi.PipeName().StartsWith("orcel-S-1-") && AppApi.PipeName().Contains("-app"), "app API pipe is this user's");
            expect(AppApi.InstanceSuffix("ci-1") == "ci-1" && AppApi.InstanceSuffix("..\\x") == null && AppApi.InstanceSuffix("A") == null && AppApi.InstanceSuffix(new string('a', 33)) == null, "instance suffix is validated");
            bool refused = false;
            try { AppApi.RequestFrame("task.stop", "rpt-1"); } catch (ArgumentException) { refused = true; }
            expect(refused, "only read-only app API methods are sent");
            expect(AppApi.RequestFrame("task.list", null) == "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"method\":\"task.list\",\"params\":{}}\n", "task.list frame");
            expect(AppApi.RequestFrame("task.get", "rpt-a").Contains("\"params\":{\"task_id\":\"rpt-a\"}"), "task.get frame");
            expect(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":false,\"error\":{\"code\":\"UNKNOWN_TASK\"}}") == null, "an error frame is not a result");
            expect(AppApi.ParseReply("{\"v\":\"other/1\",\"ok\":true,\"result\":{}}") == null, "another protocol is refused");
            expect(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[]}}") != null, "an ok frame parses");
            expect(Timeline.Text(null, new List<Dictionary<string, object>>()).StartsWith("Task timeline unavailable"), "no answer is reported, not hidden");
            Dictionary<string, object> list = AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"max_tasks\":64,\"tasks\":[{\"task_id\":\"rpt-2\"},{\"task_id\":\"rpt-1\"}]}}");
            Dictionary<string, object> two = AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"task_id\":\"rpt-2\",\"title\":\"Q3\\nsummary\",\"state\":\"verified\",\"report\":{\"destination\":\"out/q3.md\"},\"steps\":[{\"kind\":\"observe\",\"outcome\":\"ok\"},{\"kind\":\"approval\",\"outcome\":\"approved\"},{\"kind\":\"check\",\"outcome\":\"pass\"}]}}");
            string timeline = Timeline.Text(list, new List<Dictionary<string, object>> { two, null });
            expect(timeline.Contains("\"Q3 summary\": verified by the independent checker → out/q3.md"), "a verified task is shown with its report");
            expect(timeline.Contains("steps: observe ok · approval approved · check pass"), "steps are shown in order");
            expect(timeline.Contains("rpt-1: details unavailable"), "a missing detail is reported");
            expect(timeline.Contains("cannot start, approve or stop"), "the timeline states it is read-only");
            expect(Timeline.Describe("proposed").Contains("waiting for approval") && Timeline.Describe("surprise") == "unknown state", "states are described truthfully");
            expect(Timeline.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[]}}"), new List<Dictionary<string, object>>()).StartsWith("No report tasks"), "an empty run says so");
            expect(!CommandRouter.CanInvokeInstalledHost(SafeCommand.Unsupported), "unsupported never runs");
            expect(Path.IsPathRooted(LocalHost.PathToCompatCli()), "runtime path is rooted");

            RuntimeStatus installed = Interpret.Status(new CliResult { ExitCode = 0, Stdout =
                "{\"installed\":\"0.2.0\",\"ok\":true,\"runtime\":{\"detail\":\"no supervisor record\",\"state\":\"not_running\"},\"tunnel_configured\":false,\"workspaces\":0}" });
            expect(installed.Availability == RuntimeAvailability.Installed && installed.Version == "0.2.0", "status parses");
            expect(Interpret.StatusMessage(installed).Contains("not running (no supervisor record)"), "status message is truthful");
            expect(Interpret.Status(new CliResult { TimedOut = true }).Availability == RuntimeAvailability.Unresponsive, "timeout is unresponsive");
            expect(Interpret.Status(new CliResult { ExitCode = 0, Stdout = "not json" }).Availability == RuntimeAvailability.Incompatible, "garbage is incompatible");
            expect(Interpret.Status(new CliResult { ExitCode = 2, Stdout = "{\"ok\":false}" }).Availability == RuntimeAvailability.Incompatible, "error is never reported as healthy");
            string doctor = Interpret.DoctorMessage(new CliResult { ExitCode = 7, Stdout =
                "{\"doctor\":{\"checks\":[{\"name\":\"platform\",\"status\":\"pass\",\"detail\":\"ok\"},{\"name\":\"workspaces\",\"status\":\"fail\",\"detail\":\"none\"},{\"name\":\"tunnel\",\"status\":\"warn\",\"detail\":\"off\"}]}}" });
            expect(doctor.StartsWith("Health check: 1 passed, 1 warnings, 1 failed.") && doctor.Contains("FAIL workspaces: none"), "doctor summarizes failures");
            expect(Interpret.VersionMessage(new CliResult { ExitCode = 0, Stdout = "{\"cli\":\"0.2.0\",\"installed\":\"0.2.0\"}" }) == "Orcel CLI 0.2.0; installed release 0.2.0.", "version parses");

            expect(Interpret.Status(new CliResult { ExitCode = 0, Stdout = "{\"ok\":false,\"installed\":\"0.2.0\",\"runtime\":{\"state\":\"running\"}}" }).Availability == RuntimeAvailability.Incompatible, "ok:false is never healthy");
            expect(Interpret.Status(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"installed\":\"0.2.0\",\"runtime\":\"running\"}" }).Availability == RuntimeAvailability.Incompatible, "non-object runtime is incompatible");
            expect(Interpret.Status(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"installed\":\"0.2.0\",\"runtime\":{\"state\":\"runn" }).Availability == RuntimeAvailability.Incompatible, "truncated JSON is incompatible");
            expect(Interpret.Status(new CliResult { FailedToStart = true }).Availability == RuntimeAvailability.Unresponsive, "start failure is unresponsive");
            expect(Interpret.VersionMessage(new CliResult { ExitCode = 3, Stdout = "{\"cli\":\"0.2.0\"}" }).Contains("does not understand"), "version error is not a version");
            expect(BoundedProcess.Run(Path.Combine(Environment.SystemDirectory, "no-such-orcel-binary.exe"), new string[0], 1000, null).FailedToStart, "missing binary fails to start");
            expect(LocalHost.IsDriveQualified("C:\\Users\\x") && !LocalHost.IsDriveQualified("\\\\host\\share") && !LocalHost.IsDriveQualified("\\x") && !LocalHost.IsDriveQualified("C:x"), "only drive-qualified LOCALAPPDATA is used");

            // A stalled child and the process it started are both killed at the timeout.
            DateTime started = DateTime.Now.AddSeconds(-1);
            Stopwatch clock = Stopwatch.StartNew();
            CliResult stalled = BoundedProcess.Run(Path.Combine(Environment.SystemDirectory, "cmd.exe"), new[] { "/c", "ping -n 30 127.0.0.1 >nul" }, 1500, null);
            expect(stalled.TimedOut && clock.ElapsedMilliseconds < 8000, "stalled child times out");
            Thread.Sleep(500);
            bool grandchildAlive = false;
            foreach (Process ping in Process.GetProcessesByName("PING"))
            {
                using (ping)
                {
                    try { grandchildAlive |= ping.StartTime >= started; } catch (Exception) { }
                }
            }
            expect(!grandchildAlive, "timed-out child's own children are killed");
            // A child that floods stdout and stderr never deadlocks and is bounded.
            CliResult flood = BoundedProcess.Run(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                new[] { "/c", "for /L %i in (1,1,40000) do @echo flooding-stdout-and-stderr-line-%i & echo err 1>&2" }, 30000, null);
            expect(!flood.TimedOut && flood.ExitCode == 0 && flood.Truncated && flood.Stdout.Length == BoundedProcess.MaxOutputChars, "flooding child is drained and bounded");

            string dir = Path.Combine(Path.GetTempPath(), "orcel-folder-test-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                for (int i = 0; i < 40; i++) File.WriteAllText(Path.Combine(dir, "f" + i + ".txt"), "");
                string listing = FolderPreview.List(dir, CancellationToken.None);
                expect(listing.Contains("more not shown") && listing.Split('\n').Length == FolderPreview.MaxEntries + 2, "folder preview is bounded");
                bool cancelled = false;
                using (CancellationTokenSource cancel = new CancellationTokenSource())
                {
                    cancel.Cancel();
                    try { FolderPreview.List(dir, cancel.Token); } catch (OperationCanceledException) { cancelled = true; }
                }
                expect(cancelled, "folder preview honors cancellation");
                expect(FolderPreview.ListWithin(dir, TimeSpan.FromSeconds(10)).Result.Contains("more not shown"), "bounded listing completes within its limit");
                expect(FolderPreview.ListWithin(Path.Combine(dir, "missing"), TimeSpan.FromSeconds(10)).Result.StartsWith("Unable to list"), "listing failure is reported");
                // An enumeration whose first step never returns (a stalled network share).
                using (ManualResetEventSlim never = new ManualResetEventSlim(false))
                {
                    Stopwatch hung = Stopwatch.StartNew();
                    string late = FolderPreview.ListWithin(token => { never.Wait(TimeSpan.FromSeconds(30)); return "never"; }, TimeSpan.FromMilliseconds(500)).Result;
                    expect(late.Contains("stopped waiting") && hung.ElapsedMilliseconds < 5000, "hung enumeration is abandoned at the limit");
                    never.Set();
                }
            }
            finally { try { Directory.Delete(dir, true); } catch (Exception) { } }

            if (failures.Count > 0)
            {
                foreach (string failure in failures) Console.WriteLine("FAIL: " + failure);
                return 1;
            }
            Console.WriteLine("Orcel read-only router, runtime interpretation, bounded process and folder self-tests: PASS");
            return 0;
        }

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--self-test") return SelfTest();
            if (args.Length == 1 && args[0] == "--ui-self-test") { MainWindow window = new MainWindow(); if (window.Content == null) return 2; Console.WriteLine("Orcel WPF layout construction: PASS"); return 0; }
            System.Windows.Application app = new System.Windows.Application();
            // A bug must never take the window down silently; report and continue.
            bool reported = false;
            app.DispatcherUnhandledException += (sender, e) => {
                e.Handled = true;
                if (reported) return;
                reported = true;
                try
                {
                    MainWindow main = app.MainWindow as MainWindow;
                    if (main != null) main.ReportInternalError();
                }
                catch (Exception) { }
            };
            app.Run(new MainWindow());
            return 0;
        }
    }
}
