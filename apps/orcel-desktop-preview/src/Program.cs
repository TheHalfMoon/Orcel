// Orcel Desktop Foundation — read-only Windows preview.
// This preview never sends screenshots or text to a model, network, or remote device.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
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
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;


namespace Orcel.DesktopPreview
{
    internal enum SafeCommand { Help, Status, Version, Doctor, Devices, Files, Tasks, History, Previews, PreviewsSizes, PreviewsContent, Control, StopControl, RevokeAll, Unsupported }

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
            if (value == "history") return SafeCommand.History;
            if (value == "previews") return SafeCommand.Previews;
            if (value == "previews sizes") return SafeCommand.PreviewsSizes;
            if (value == "previews content") return SafeCommand.PreviewsContent;
            if (value == "control") return SafeCommand.Control;
            if (value == "stop control") return SafeCommand.StopControl;
            if (value == "revoke all") return SafeCommand.RevokeAll;
            return SafeCommand.Unsupported;
        }

        internal static bool CanInvokeInstalledHost(SafeCommand command)
        {
            return command == SafeCommand.Status || command == SafeCommand.Version || command == SafeCommand.Doctor
                || IsPreviewSetting(command) || IsControl(command);
        }

        /// Desktop control: its status, and the two ways to take authority away. The app can
        /// stop or revoke; it never grants (`orcel full-control grant` stays in a terminal,
        /// behind Windows Hello).
        internal static bool IsControl(SafeCommand command)
        {
            return command == SafeCommand.Control || command == SafeCommand.StopControl || command == SafeCommand.RevokeAll;
        }

        /// `previews content` is recognised only to say where to do it: the app never asks for
        /// more disclosure, so a stray click or an automated agent typing into it can't loosen
        /// what approval prompts show.
        internal static bool IsPreviewSetting(SafeCommand command)
        {
            return command == SafeCommand.Previews || command == SafeCommand.PreviewsSizes;
        }

        /// The only arguments ever passed to the runtime: fixed, read-only queries, and one
        /// privacy setting (`approvals previews sizes`) that makes approval prompts show sizes
        /// only. It saves one field in Orcel's protected configuration and changes nothing else.
        internal static string[] CliArguments(SafeCommand command)
        {
            if (command == SafeCommand.Status) return new[] { "status", "--json" };
            if (command == SafeCommand.Version) return new[] { "version", "--json" };
            if (command == SafeCommand.Doctor) return new[] { "doctor", "--json" };
            if (command == SafeCommand.Previews) return new[] { "approvals", "previews", "--json" };
            if (command == SafeCommand.PreviewsSizes) return new[] { "approvals", "previews", "sizes", "--json" };
            if (command == SafeCommand.Control) return new[] { "full-control", "status", "--json" };
            if (command == SafeCommand.StopControl) return new[] { "full-control", "revoke", "--json" };
            if (command == SafeCommand.RevokeAll) return new[] { "emergency-revoke", "--json" };
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
        internal static CliResult Run(string fileName, string[] arguments, int timeoutMs, string userProfile)
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
                if (userProfile != null) process.StartInfo.EnvironmentVariables["USERPROFILE"] = userProfile;
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

    /// Failed: the runtime answered with its own error, which the app shows as it is.
    internal enum RuntimeAvailability { NotInstalled, Unresponsive, Incompatible, Failed, Installed }

    /// What the app truthfully knows about the local Orcel runtime.
    internal sealed class RuntimeStatus
    {
        internal RuntimeAvailability Availability;
        internal string Version;
        internal string State;
        internal string Detail;
        internal int? Workspaces;
        /// Null when the status didn't say.
        internal bool? TunnelConfigured;

        /// The background runtime `orcel start` runs carries only the optional ChatGPT tunnel;
        /// local MCP clients start Orcel themselves, so "not running" never means Orcel is down.
        internal string Tunnel()
        {
            if (Unconfigured()) return "ChatGPT tunnel not configured (optional)";
            return "ChatGPT tunnel " + Describe(State);
        }

        /// As the CLI decides it: no tunnel configured and no supervisor record at all. A stale
        /// record keeps its detail.
        internal bool Unconfigured()
        {
            return TunnelConfigured == false && State == "not_running" && Detail == "no supervisor record";
        }

        internal string Headline()
        {
            switch (Availability)
            {
                case RuntimeAvailability.NotInstalled: return "Not installed";
                case RuntimeAvailability.Unresponsive: return "Installed • not responding";
                case RuntimeAvailability.Incompatible: return "Installed • incompatible response";
                case RuntimeAvailability.Failed: return "Installed • status reported an error";
                default: return "Orcel runtime " + Version + " • " + Tunnel();
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
        /// %USERPROFILE%, as the runtime uses, then the known folder, which the
        /// runtime lacks: this app passes what it finds to its child, so they agree.
        /// Never PATH, never a model- or user-provided path.
        internal static string UserProfile()
        {
            string fromEnvironment = Environment.GetEnvironmentVariable("USERPROFILE");
            if (IsDriveQualified(fromEnvironment)) return fromEnvironment;
            return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        }

        /// `C:\...` only: no UNC share (`\\host\share`), no drive-relative path.
        internal static bool IsDriveQualified(string path)
        {
            return !string.IsNullOrEmpty(path) && path.Length >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
                && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
        }

        internal static string PathToCompatCli()
        {
            return Path.Combine(UserProfile(), ".orcel", "bin", "orcel.exe");
        }

        internal static bool IsInstalled()
        {
            return File.Exists(PathToCompatCli());
        }

        internal static CliResult Query(SafeCommand command, int timeoutMs)
        {
            string[] arguments = CommandRouter.CliArguments(command);
            if (arguments == null) throw new ArgumentException("not a runtime query this app may run");
            return BoundedProcess.Run(PathToCompatCli(), arguments, timeoutMs, UserProfile());
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
    /// and `task.get`, one request per connection, and `events.subscribe`
    /// (see TaskWatcher) to this user's pipe
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
        /// The only methods this client sends; all are read-only in orceld.
        internal static readonly string[] Methods = { "task.list", "task.get", "events.subscribe", "approval.history" };

        /// This user's pipe name, or null when ORCEL_APP_API_INSTANCE is set
        /// but invalid (refused, never replaced by the default pipe).
        internal static string PipeName()
        {
            string sid = WindowsIdentity.GetCurrent().User.Value;
            string raw = Environment.GetEnvironmentVariable("ORCEL_APP_API_INSTANCE");
            if (string.IsNullOrEmpty(raw)) return "orcel-" + sid + "-app";
            string suffix = InstanceSuffix(raw);
            return suffix == null ? null : "orcel-" + sid + "-app-" + suffix;
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
            if (method == "approval.history") parameters["limit"] = ApprovalHistory.MaxShown;
            request["params"] = parameters;
            return new JavaScriptSerializer().Serialize(request) + "\n";
        }

        /// `epoch` is required with a cursor, and `after_seq` 0 may omit it.
        internal static string SubscribeFrame(long afterSeq, string epoch)
        {
            Dictionary<string, object> request = new Dictionary<string, object>();
            request["v"] = Protocol;
            request["id"] = "desktop";
            request["method"] = "events.subscribe";
            Dictionary<string, object> parameters = new Dictionary<string, object>();
            parameters["after_seq"] = afterSeq;
            if (afterSeq > 0) parameters["epoch"] = epoch ?? "";
            request["params"] = parameters;
            return new JavaScriptSerializer().Serialize(request) + "\n";
        }

        /// One request on its own connection, at most TimeoutMs in all; null
        /// when the pipe is absent, its server is not this user at Medium
        /// integrity or above, or the answer is late or unusable. On timeout
        /// the pipe is disposed, which cancels the pending read.
        internal static Dictionary<string, object> Call(string method, string taskId)
        {
            string frame = RequestFrame(method, taskId);
            string name = PipeName();
            if (name == null) return null;
            Stopwatch clock = Stopwatch.StartNew();
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
            {
                try
                {
                    pipe.Connect(TimeoutMs);
                    if (!ServerIsThisUser(pipe)) return null;
                    byte[] bytes = Encoding.UTF8.GetBytes(frame);
                    if (!pipe.WriteAsync(bytes, 0, bytes.Length).Wait(Remaining(clock))) return null;
                    return ParseReply(ReadFrame(pipe, clock));
                }
                catch (Exception) { return null; }
            }
        }

        private static int Remaining(Stopwatch clock)
        {
            return Math.Max(0, TimeoutMs - (int)clock.ElapsedMilliseconds);
        }

        /// One frame, newline included at most MaxFrameBytes, before the deadline.
        private static string ReadFrame(Stream stream, Stopwatch clock)
        {
            MemoryStream frame = new MemoryStream();
            byte[] chunk = new byte[4096];
            while (true)
            {
                Task<int> read = stream.ReadAsync(chunk, 0, chunk.Length);
                if (!read.Wait(Remaining(clock)) || read.Result <= 0) return null;
                for (int i = 0; i < read.Result; i++)
                {
                    if (chunk[i] == '\n') return Encoding.UTF8.GetString(frame.ToArray());
                    if (frame.Length >= MaxFrameBytes - 1) return null;
                    frame.WriteByte(chunk[i]);
                }
            }
        }

        /// ORCEL_APP_API_1.md section 7: the pipe name is predictable, so the
        /// server must run as this user, at Medium integrity or above, before
        /// anything it says is shown.
        internal static bool ServerIsThisUser(NamedPipeClientStream pipe)
        {
            uint pid;
            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out pid) || pid == 0) return false;
            return ProcessRunsAsThisUser(pid);
        }

        internal static bool ProcessRunsAsThisUser(uint pid)
        {
            IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (process == IntPtr.Zero) return false;
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(process, TokenQuery, out token)) return false;
                SecurityIdentifier user = TokenSid(token, TokenUserClass);
                SecurityIdentifier label = TokenSid(token, TokenIntegrityLevelClass);
                if (user == null || label == null || !user.Equals(WindowsIdentity.GetCurrent().User)) return false;
                // The mandatory label's last sub-authority is the level: 0x2000 is Medium.
                string[] parts = label.Value.Split('-');
                uint level;
                return uint.TryParse(parts[parts.Length - 1], out level) && level >= 0x2000;
            }
            finally
            {
                if (token != IntPtr.Zero) CloseHandle(token);
                CloseHandle(process);
            }
        }

        /// TokenUser and TokenIntegrityLevel both start with a SID_AND_ATTRIBUTES.
        private static SecurityIdentifier TokenSid(IntPtr token, int infoClass)
        {
            int length;
            GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out length);
            if (length <= 0 || length > 4096) return null;
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, infoClass, buffer, length, out length)) return null;
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
            }
            catch (Exception) { return null; }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private const uint ProcessQueryLimitedInformation = 0x1000;
        private const uint TokenQuery = 0x0008;
        private const int TokenUserClass = 1;
        private const int TokenIntegrityLevelClass = 25;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

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

        internal static string ShownText(string value) { return Shown(value); }

        private static string Shown(string value)
        {
            if (value == null) return "(none)";
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                if (text.Length >= MaxTitleChars) { text.Append("…"); break; }
                char c = value[i];
                if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                {
                    text.Append(c).Append(value[++i]);
                    continue;
                }
                text.Append(Safe(c));
            }
            return text.ToString();
        }

        /// Planner and workspace text may not start a line, reorder the
        /// display or close the quotes around a title.
        internal static char Safe(char c)
        {
            switch (CharUnicodeInfo.GetUnicodeCategory(c))
            {
                case UnicodeCategory.Control:
                case UnicodeCategory.Format:
                case UnicodeCategory.LineSeparator:
                case UnicodeCategory.ParagraphSeparator:
                case UnicodeCategory.Surrogate:
                    return ' ';
            }
            return c == '"' ? '\'' : c;
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
                case "stopped": return "stopped";
                default: return "unknown state";
            }
        }

        private static int TaskCount(Dictionary<string, object> list)
        {
            object tasks;
            int count = 0;
            if (list != null && list.TryGetValue("tasks", out tasks) && tasks is IEnumerable)
                foreach (object task in (IEnumerable)tasks) count++;
            return count;
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
                return "Task timeline unavailable: this user's app API pipe did not answer, gave an unusable answer, or is not served by this user at normal integrity (the runtime may not be running). Nothing was changed.";
            List<string> ids = NewestIds(list);
            if (ids.Count == 0) return "No report tasks in this orceld run. Tasks are started by a connected local MCP client; this app only shows them.";
            StringBuilder text = new StringBuilder();
            int total = TaskCount(list);
            text.Append("Report tasks orceld knows of, newest first (showing " + ids.Count + " of " + total + "; titles and paths come from the planner and the workspace and are not verified):");
            for (int i = 0; i < ids.Count; i++)
            {
                Dictionary<string, object> task = i < tasks.Count ? tasks[i] : null;
                if (task == null) { text.Append("\n• " + ids[i] + ": details unavailable"); continue; }
                text.Append("\n• " + Describe(Field(task, "state")) + ": \"" + Shown(Field(task, "title")) + "\"");
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

    /// The approval history as text: decisions orceld recorded, newest first, with where each
    /// request came from. It reads only; nothing here approves, denies or revokes.
    internal static class ApprovalHistory
    {
        internal const int MaxShown = 10;

        private static string Field(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : null;
        }

        internal static string Origin(object value)
        {
            Dictionary<string, object> origin = value as Dictionary<string, object>;
            string kind = Field(origin, "kind");
            if (kind == "local") return "this computer";
            if (kind == "remote")
                return "REMOTE via " + Timeline.ShownText(Field(origin, "provider")) + ", device " + Timeline.ShownText(Field(origin, "device"));
            return "origin not recorded";
        }

        internal static string Decision(string decision)
        {
            switch (decision)
            {
                case "Approved": return "approved";
                case "Denied": return "denied";
                case "Unavailable": return "not approved (unavailable)";
                default: return "unknown decision";
            }
        }

        internal static string When(string millis)
        {
            long ms;
            if (!long.TryParse(millis, out ms) || ms <= 0) return "(time unknown)";
            try { return DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"); }
            catch (ArgumentOutOfRangeException) { return "(time unknown)"; }
        }

        internal static string Text(Dictionary<string, object> result)
        {
            if (result == null) return "Approval history unavailable: the local runtime did not answer, or this version of it has no approval history to read.";
            object entries;
            if (!result.TryGetValue("entries", out entries) || !(entries is IEnumerable)) return "Approval history unavailable: the answer had no entries.";
            StringBuilder text = new StringBuilder("Recent approval decisions, newest first:");
            int shown = 0;
            foreach (object item in (IEnumerable)entries)
            {
                Dictionary<string, object> entry = item as Dictionary<string, object>;
                if (entry == null) continue;
                if (shown++ >= MaxShown) break;
                string line = When(Field(entry, "decided_at_ms")) + "  " + Decision(Field(entry, "decision"))
                    + " (" + Timeline.ShownText(Field(entry, "approval_class")) + ")"
                    + ", from " + Origin(entry.ContainsKey("origin") ? entry["origin"] : null)
                    + ", workspace " + Timeline.ShownText(Field(entry, "workspace_id"));
                if (Field(entry, "is_revoke") == "True") line += ", emergency revoke";
                else if (Field(entry, "consumed") == "True") line += ", used";
                text.Append("\n• ").Append(line);
            }
            if (shown == 0) return "No approval decisions are recorded yet.";
            text.Append("\nThis app reads the history only; approvals are answered in the system's own prompt.");
            return text.ToString();
        }

        internal static string Read()
        {
            return Text(AppApi.Call("approval.history", null));
        }
    }

    /// Splits a stream into frames, keeping what follows a newline for the next
    /// one. A frame over MaxFrameBytes, a read past its deadline, or the end of the
    /// stream gives null, and the connection is finished.
    internal sealed class FrameReader
    {
        private readonly Stream stream;
        private readonly byte[] chunk = new byte[4096];
        private int start;
        private int end;

        internal FrameReader(Stream stream) { this.stream = stream; }

        internal string Next(int deadlineMs, CancellationToken stop)
        {
            MemoryStream frame = new MemoryStream();
            while (true)
            {
                while (start < end)
                {
                    byte value = chunk[start++];
                    if (value == (byte)'\n') return Encoding.UTF8.GetString(frame.ToArray());
                    if (frame.Length >= AppApi.MaxFrameBytes - 1) return null;
                    frame.WriteByte(value);
                }
                Task<int> read = stream.ReadAsync(chunk, 0, chunk.Length);
                if (!read.Wait(deadlineMs, stop) || read.Result <= 0) return null;
                start = 0;
                end = read.Result;
            }
        }
    }

    /// Where a subscription has reached in one orceld run.
    internal sealed class WatchCursor
    {
        internal long AfterSeq;
        internal string Epoch;
        /// Events up to here happened before this app was watching: they're
        /// history, which `tasks` shows, so they aren't announced as news.
        internal long QuietThrough = -1;
        /// Updates may have been missed, so the next connection shows the list.
        internal bool Refresh;
    }

    /// The task timeline, live: follows orceld's `task.updated` events and shows
    /// each as it happens, so "waiting for approval" appears without asking. After a
    /// gap, such as orceld restarting, it shows the current list instead. Read
    /// only, like everything in this app: once subscribed it sends nothing more,
    /// and each connection checks that the server is this user, as AppApi does. The
    /// text comes from a closed list of states and a task id made safe to show.
    internal static class TaskWatcher
    {
        /// orceld sends a heartbeat after 15 s without events.
        internal const int SilenceMs = 45000;
        internal const int RetryMs = 5000;

        private static long Number(object value)
        {
            try { return Convert.ToInt64(value, CultureInfo.InvariantCulture); }
            catch (Exception) { return -1; }
        }

        private static string Text(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) ? value as string : null;
        }

        /// Reads one frame into the cursor. Returns text to show, or null. `finished`
        /// says this connection has nothing more to give: an error, or the snapshot
        /// that precedes the server closing it.
        internal static string Apply(string line, WatchCursor cursor, out bool finished)
        {
            finished = false;
            Dictionary<string, object> frame;
            try { frame = new JavaScriptSerializer { MaxJsonLength = AppApi.MaxFrameBytes }.DeserializeObject(line) as Dictionary<string, object>; }
            catch (Exception) { finished = true; return null; }
            object value;
            if (frame == null || !frame.TryGetValue("v", out value) || !AppApi.Protocol.Equals(value)) { finished = true; return null; }
            if (frame.TryGetValue("ok", out value))
            {
                Dictionary<string, object> result = frame.TryGetValue("result", out value) ? value as Dictionary<string, object> : null;
                if (!true.Equals(frame["ok"]) || result == null)
                {
                    finished = true;
                    object failure;
                    Dictionary<string, object> error = frame.TryGetValue("error", out failure) ? failure as Dictionary<string, object> : null;
                    // Too many clients for now: the same cursor is still good.
                    if (Text(error, "code") == "BUSY") return null;
                    // A cursor orceld won't take: start over, with what was missed
                    // shown as the current list rather than replayed as news.
                    cursor.AfterSeq = 0;
                    cursor.Epoch = null;
                    cursor.QuietThrough = -1;
                    cursor.Refresh = true;
                    return null;
                }
                // Only a fresh subscription learns its epoch here. With a cursor, the
                // cursor's own epoch stands until a snapshot replaces it.
                if (cursor.AfterSeq == 0) cursor.Epoch = Text(result, "epoch");
                if (cursor.QuietThrough < 0 && result.TryGetValue("head_seq", out value)) cursor.QuietThrough = Number(value);
                return null;
            }
            if (!frame.TryGetValue("event", out value)) return null;
            Dictionary<string, object> received = value as Dictionary<string, object>;
            if (received == null) { finished = true; return null; }
            string kind = Text(received, "kind");
            Dictionary<string, object> data = received.TryGetValue("data", out value) ? value as Dictionary<string, object> : null;
            if (kind == "snapshot")
            {
                Dictionary<string, object> next = data != null && data.TryGetValue("resubscribe", out value) ? value as Dictionary<string, object> : null;
                long after = next != null && next.TryGetValue("after_seq", out value) ? Number(value) : -1;
                cursor.AfterSeq = after > 0 ? after : 0;
                cursor.Epoch = Text(next, "epoch");
                // What follows is new, including a new run's low sequence numbers.
                // What came before wasn't seen: the next connection shows the list.
                cursor.QuietThrough = cursor.AfterSeq;
                cursor.Refresh = true;
                finished = true;
                return null;
            }
            long seq = received.TryGetValue("seq", out value) ? Number(value) : -1;
            if (seq < 0) { finished = true; return null; }
            cursor.AfterSeq = seq;
            if (kind != "task.updated" || seq <= cursor.QuietThrough) return null;
            string id = Text(received, "run_id");
            if (id == null) return null;
            return "Task " + Timeline.ShownText(id) + ": " + Timeline.Describe(Text(data, "state")) + ".";
        }

        /// Until `stop`: subscribes, shows what happens and, if the connection ends
        /// or orceld isn't there, tries again. Never throws.
        internal static void Run(Action<string> show, CancellationToken stop)
        {
            WatchCursor cursor = new WatchCursor();
            while (!stop.IsCancellationRequested)
            {
                string name = AppApi.PipeName();
                if (name == null) return;
                try { Follow(name, cursor, show, stop); }
                catch (Exception) { }
                // Not yet connected: orceld may start in the wait, and what it does
                // before the next try would pass as history.
                if (cursor.QuietThrough < 0) cursor.Refresh = true;
                if (stop.WaitHandle.WaitOne(RetryMs)) return;
            }
        }

        private static void Follow(string name, WatchCursor cursor, Action<string> show, CancellationToken stop)
        {
            using (NamedPipeClientStream pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification))
            {
                pipe.Connect(AppApi.TimeoutMs);
                if (!AppApi.ServerIsThisUser(pipe)) return;
                byte[] bytes = Encoding.UTF8.GetBytes(AppApi.SubscribeFrame(cursor.AfterSeq, cursor.Epoch));
                if (!pipe.WriteAsync(bytes, 0, bytes.Length).Wait(AppApi.TimeoutMs, stop)) return;
                FrameReader frames = new FrameReader(pipe);
                while (true)
                {
                    string line = frames.Next(SilenceMs, stop);
                    if (line == null) return;
                    bool finished;
                    string text = Apply(line, cursor, out finished);
                    if (text != null) show(text);
                    if (cursor.Refresh && !finished)
                    {
                        cursor.Refresh = false;
                        show("Task updates may have been missed. The current list:\n" + Timeline.Read());
                    }
                    if (finished) return;
                }
            }
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
            object error;
            // The CLI's own error, such as a corrupt record: shown, never treated as healthy.
            if (json != null && result.ExitCode != 0 && json.ContainsKey("ok") && false.Equals(json["ok"])
                && json.TryGetValue("error", out error) && !string.IsNullOrEmpty(Text(error as Dictionary<string, object>, "message")))
            {
                string message = Plain(Text((Dictionary<string, object>)error, "message"));
                // A message that cleans to nothing says nothing, so it's an answer this app doesn't understand.
                if (message != ".") return new RuntimeStatus { Availability = RuntimeAvailability.Failed, Detail = message };
            }
            if (json == null || result.ExitCode != 0 || !(json.ContainsKey("ok") && true.Equals(json["ok"]))
                || !json.TryGetValue("runtime", out runtime) || !(runtime is Dictionary<string, object>))
                return new RuntimeStatus { Availability = RuntimeAvailability.Incompatible };
            Dictionary<string, object> runtimeMap = (Dictionary<string, object>)runtime;
            string version = Text(json, "installed");
            if (version == null) return new RuntimeStatus { Availability = RuntimeAvailability.NotInstalled };
            int workspaces;
            object tunnel;
            return new RuntimeStatus {
                Availability = RuntimeAvailability.Installed,
                Version = version,
                State = Text(runtimeMap, "state"),
                Detail = Text(runtimeMap, "detail"),
                Workspaces = int.TryParse(Text(json, "workspaces"), out workspaces) ? (int?)workspaces : null,
                TunnelConfigured = json.TryGetValue("tunnel_configured", out tunnel) && tunnel is bool ? (bool?)(bool)tunnel : null
            };
        }

        /// Runtime text can quote a state file, so it may not start a line or reorder the display.
        /// Unlike a title it isn't cut: it carries whole paths. It ends as a sentence.
        internal static string Plain(string value)
        {
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (char.IsHighSurrogate(c) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                {
                    text.Append(c).Append(value[++i]);
                    continue;
                }
                text.Append(Timeline.Safe(c));
            }
            string plain = text.ToString().Trim();
            return plain.EndsWith(".") || plain.EndsWith("!") || plain.EndsWith("?") ? plain : plain + ".";
        }

        internal static string StatusMessage(RuntimeStatus status)
        {
            if (status.Availability == RuntimeAvailability.NotInstalled)
                return "The Orcel runtime is not installed for this Windows user. No operation was attempted. "
                    + "Next: in a terminal in the extracted release folder, run `.\\orcel.exe install`, then Refresh status.";
            if (status.Availability == RuntimeAvailability.Unresponsive)
                return "The Orcel runtime did not answer a read-only status query in time. No action was performed. "
                    + "Next: Refresh status. If it keeps failing, repair the install with `.\\orcel.exe install` from the extracted release folder of the same version.";
            if (status.Availability == RuntimeAvailability.Incompatible)
                return "The installed Orcel runtime returned a response this preview does not understand. No action was performed. "
                    + "Next: use this app from the same release as the installed runtime; `version` shows the installed release.";
            if (status.Availability == RuntimeAvailability.Failed)
                return "Orcel status reported an error: " + status.Detail + " No action was performed. `doctor` runs the full health check.";
            StringBuilder text = new StringBuilder();
            text.Append("Orcel runtime ").Append(status.Version).Append(" is installed. ").Append(status.Tunnel());
            if (!string.IsNullOrEmpty(status.Detail) && !status.Unconfigured())
                text.Append(" (").Append(status.Detail).Append(")");
            text.Append(".");
            if (status.Workspaces.HasValue) text.Append(" Workspaces configured: ").Append(status.Workspaces.Value).Append(".");
            if (status.Workspaces == 0)
                text.Append(" Next: add the folder Orcel may work in with `orcel workspace add <id> <folder>` in a terminal.");
            return text.ToString();
        }

        /// The runtime's own refusal, escaped, or null.
        private static string Refusal(CliResult result, Dictionary<string, object> answer)
        {
            object error;
            if (answer != null && result.ExitCode != 0 && answer.TryGetValue("error", out error)
                && !string.IsNullOrEmpty(Text(error as Dictionary<string, object>, "message")))
                return Plain(Text((Dictionary<string, object>)error, "message"));
            return null;
        }

        private static Dictionary<string, object> Ok(CliResult result, Dictionary<string, object> answer)
        {
            return result.ExitCode == 0 && answer != null && answer.ContainsKey("ok") && true.Equals(answer["ok"]) ? answer : null;
        }

        /// `orcel full-control status --json`.
        internal static string ControlMessage(CliResult result)
        {
            if (result.FailedToStart || result.TimedOut) return "The Orcel runtime did not answer the desktop control status in time.";
            Dictionary<string, object> answer = Parse(result.Stdout);
            string refusal = Refusal(result, answer);
            if (refusal != null) return "The Orcel runtime could not read desktop control: " + refusal;
            Dictionary<string, object> json = Ok(result, answer);
            object raw;
            Dictionary<string, object> status = json != null && json.TryGetValue("full_control", out raw) ? raw as Dictionary<string, object> : null;
            if (status == null) return "The installed Orcel runtime did not report desktop control in a form this app understands.";
            object active;
            if (status.TryGetValue("active", out active) && true.Equals(active))
                return "Desktop control is ACTIVE: Orcel may type and click in this session until its lease ends. Type stop control, or press Stop desktop control, to end it now.";
            string reason = Text(status, "reason");
            return "Desktop control is off (Safe)" + (string.IsNullOrEmpty(reason) ? ": no active lease for this session." : ": " + Plain(reason));
        }

        /// `orcel full-control revoke --json`.
        internal static string StopControlMessage(CliResult result)
        {
            if (result.FailedToStart) return "The Orcel runtime could not be started, so desktop control was not stopped by this app. Run orcel full-control revoke in a terminal.";
            if (result.TimedOut) return "The Orcel runtime did not answer in time. Desktop control may or may not have stopped; type control to check, or run orcel full-control revoke in a terminal.";
            Dictionary<string, object> answer = Parse(result.Stdout);
            string refusal = Refusal(result, answer);
            if (refusal != null) return "Desktop control was NOT confirmed stopped: " + refusal + " Run orcel full-control revoke in a terminal.";
            Dictionary<string, object> json = Ok(result, answer);
            if (json == null) return "The installed Orcel runtime did not confirm that desktop control stopped. Type control to check.";
            object revoked;
            json.TryGetValue("revoked", out revoked);
            if (true.Equals(revoked))
                return "Desktop control authority revoked. Orcel can't type or click until someone grants it again with Windows Hello.";
            if (false.Equals(revoked))
                return "Desktop control was already off (Safe). Nothing was running.";
            return "The installed Orcel runtime did not confirm that desktop control stopped. Type control to check.";
        }

        /// `orcel emergency-revoke --json`: the runtime asks for Windows Hello itself.
        internal static string RevokeAllMessage(CliResult result)
        {
            if (result.FailedToStart) return "The Orcel runtime could not be started, so nothing was revoked by this app. Run orcel emergency-revoke in a terminal.";
            if (result.TimedOut) return "The emergency revoke did not finish in time. It may or may not have been recorded; type history, or run orcel approvals in a terminal, to check.";
            Dictionary<string, object> answer = Parse(result.Stdout);
            string refusal = Refusal(result, answer);
            // An error can follow a partial revoke, or a Hello approved after the CLI stopped
            // waiting, so it never claims that nothing happened.
            if (refusal != null) return "The emergency revoke was not confirmed: " + refusal + " Type history, or run orcel approvals in a terminal, to see whether it was recorded.";
            if (Ok(result, answer) == null) return "The installed Orcel runtime did not confirm the emergency revoke. Type history, or run orcel approvals in a terminal, to see whether it was recorded.";
            return "Emergency revoke recorded: every pending approval, desktop control and every remote session lease is now invalid.";
        }

        /// `orcel approvals previews [sizes|content] --json`: what approval prompts show of the
        /// content they approve. Only the runtime's own answer is reported.
        internal static string PreviewsMessage(CliResult result)
        {
            if (result.FailedToStart) return "The Orcel runtime could not be started. The approval preview setting was not changed.";
            if (result.TimedOut) return "The Orcel runtime did not answer the approval preview setting in time. It may or may not have been saved; type previews to check.";
            Dictionary<string, object> answer = Parse(result.Stdout);
            object error;
            if (answer != null && result.ExitCode != 0 && answer.TryGetValue("error", out error)
                && !string.IsNullOrEmpty(Text(error as Dictionary<string, object>, "message")))
                return "The Orcel runtime answered the approval preview command with an error: " + Plain(Text((Dictionary<string, object>)error, "message"))
                    + " If the runtime is older than this app, it may not have this setting; update Orcel.";
            Dictionary<string, object> json = result.ExitCode == 0 && answer != null && answer.ContainsKey("ok") && true.Equals(answer["ok"]) ? answer : null;
            string choice = Text(json, "approval_previews");
            object changed = null;
            if (json != null) json.TryGetValue("changed", out changed);
            if (choice == "sizes")
                return "Approval previews: sizes only. Approval prompts show how much would change, never the content."
                    + (true.Equals(changed) ? " Saved. Restart your AI clients so their next sessions use it." : "");
            if (choice == "content")
                return "Approval previews: a short preview, hidden when it looks like a password, key or token."
                    + (true.Equals(changed) ? " Saved. Restart your AI clients so their next sessions use it." : "")
                    + " Type previews sizes to show sizes only. (ORCEL_APPROVAL_PREVIEWS=sizes in your environment also does.)";
            return "The installed Orcel runtime did not report an approval preview setting this app understands. It may be older than this app.";
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
        /// Windows high contrast replaces the dark palette with the system's own colours, so
        /// text, borders and buttons keep the contrast the person chose. Read when the app
        /// starts; a change applies the next time it opens.
        internal static readonly bool HighContrast = SystemParameters.HighContrast;
        internal static Brush Ink = Choose(HighContrast, "#E9EDFA", SystemColors.WindowTextBrush);
        internal static Brush Muted = Choose(HighContrast, "#9BA7C5", SystemColors.WindowTextBrush);
        internal static Brush Background = Choose(HighContrast, "#090D19", SystemColors.WindowBrush);
        internal static Brush Sidebar = Choose(HighContrast, "#111729", SystemColors.WindowBrush);
        internal static Brush Surface = Choose(HighContrast, "#161E34", SystemColors.WindowBrush);
        internal static Brush Border = Choose(HighContrast, "#29334C", SystemColors.WindowTextBrush);
        internal static Brush Accent = Choose(HighContrast, "#9A8CF5", SystemColors.HighlightBrush);
        /// Text on an accent-coloured button: the pair Windows defines for highlighted items.
        internal static Brush OnAccent = Choose(HighContrast, "#090D19", SystemColors.HighlightTextBrush);
        internal static Brush Safe = Choose(HighContrast, "#73D6BD", SystemColors.WindowTextBrush);
        internal static Brush Bubble = Choose(HighContrast, "#222F4D", SystemColors.WindowBrush);

        internal static Brush Choose(bool highContrast, string dark, Brush system)
        {
            return highContrast ? system : Hex(dark);
        }

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
        /// An emergency revoke's call to orceld is limited to 180 s (its STRONG summary and
        /// Windows Hello each wait up to 120 s); this covers that and the CLI's start.
        private const int RevokeAllTimeoutMs = 200000;
        /// Desktop control commands may wait up to 60 s for the runtime's lifecycle lock, for
        /// example while an update runs or a grant waits for Windows Hello.
        private const int ControlTimeoutMs = 70000;
        private readonly StackPanel transcript = new StackPanel();
        /// A polite live region: each reply is read out by a screen reader when it arrives,
        /// without moving focus from the command box.
        private readonly TextBlock announcer = new TextBlock();
        internal const int MaxAnnouncedChars = 400;
        private readonly TextBox commandBox = new TextBox();
        private readonly TextBlock hostState = new TextBlock();
        private readonly TextBlock deviceState = new TextBlock();
        private readonly ScrollViewer conversation = new ScrollViewer();
        private readonly CancellationTokenSource watching = new CancellationTokenSource();
        private bool refreshing;
        private int messages;
        // #288: each message keeps its own visuals (text layout, bubble,
        // automation peer) for the life of the window; measured on CI, the
        // native footprint grew by about 0.2 MB per query and was never
        // released. The transcript keeps the most recent messages only.
        internal const int MaxTranscriptMessages = 200;

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
            Loaded += delegate { RefreshHost(); commandBox.Focus(); WatchTasks(); };
            Closed += delegate { watching.Cancel(); };
        }

        /// Task updates, as they happen. Invoke, not BeginInvoke: a window that can't
        /// keep up slows the reader, and orceld then sends a snapshot instead of
        /// the window's queue growing.
        private void WatchTasks()
        {
            CancellationToken stop = watching.Token;
            Task.Run(delegate {
                TaskWatcher.Run(text => {
                    if (!stop.IsCancellationRequested) Dispatcher.Invoke(delegate { AddMessage(false, text); });
                }, stop);
            });
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
                Foreground = enabled ? Colors.OnAccent : Colors.Muted,
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
            TextBlock stage = Text("DESKTOP FOUNDATION  •  READ-ONLY + STOP CONTROLS", 11, Colors.Safe, true);
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
            TextBlock sub = Text("It reports the real local runtime and never executes free text. It changes things only to take authority away: sizes-only previews, stopping desktop control, and an emergency revoke. Orcel AI and remote actions are not connected.", 12, Colors.Muted, false);
            sub.Margin = new Thickness(0, 6, 0, 0);
            headline.Children.Add(sub);
            center.Children.Add(headline);

            conversation.VerticalScrollBarVisibility = ScrollBarVisibility.Auto;
            conversation.Content = transcript;
            AutomationProperties.SetAutomationId(conversation, "Transcript");
            AutomationProperties.SetName(conversation, "Conversation transcript");
            AutomationProperties.SetAutomationId(announcer, "Announcement");
            AutomationProperties.SetLiveSetting(announcer, AutomationLiveSetting.Polite);
            announcer.FontSize = 1;
            announcer.Opacity = 0;
            announcer.IsHitTestVisible = false;
            announcer.Focusable = false;
            center.Children.Add(announcer);
            Border transcriptCard = Card(conversation, Colors.Sidebar, new Thickness(14));
            Grid.SetRow(transcriptCard, 1);
            center.Children.Add(transcriptCard);
            AddMessage(false, "Welcome to Orcel. Type help to see the commands, such as status, tasks, history, control or stop control. Other requests are not executed or sent anywhere.");

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
            commandBox.ToolTip = "Commands: help, status, version, doctor, devices, files, tasks, history, previews, control, stop control, revoke all";
            AutomationProperties.SetAutomationId(commandBox, "CommandBox");
            AutomationProperties.SetName(commandBox, "Command");
            AutomationProperties.SetHelpText(commandBox, "Type a command and press Enter; all are read-only except previews sizes, stop control and revoke all, which only take authority away");
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
            deviceState.TextWrapping = TextWrapping.Wrap;
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
            System.Windows.Controls.Button stopControl = ActionButton("Stop desktop control", true, "StopControlButton");
            stopControl.Margin = new Thickness(0, 10, 0, 0);
            AutomationProperties.SetHelpText(stopControl, "Ends Orcel's Full User desktop control at once; it never grants control");
            stopControl.Click += delegate { AddMessage(true, "stop control"); QueryHost(SafeCommand.StopControl); };
            runtime.Children.Add(stopControl);
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
            while (transcript.Children.Count > MaxTranscriptMessages) transcript.Children.RemoveAt(0);
            conversation.ScrollToEnd();
            if (!fromUser) Announce(message);
        }

        /// What a screen reader hears for a reply: the reply, cut at MaxAnnouncedChars.
        internal static string Announcement(string message)
        {
            string text = (message ?? "").Trim();
            return text.Length <= MaxAnnouncedChars ? text : text.Substring(0, MaxAnnouncedChars) + "…";
        }

        private void Announce(string message)
        {
            announcer.Text = Announcement(message);
            AutomationPeer peer = UIElementAutomationPeer.FromElement(announcer) ?? UIElementAutomationPeer.CreatePeerForElement(announcer);
            if (peer != null) peer.RaiseAutomationEvent(AutomationEvents.LiveRegionChanged);
        }

        /// #288: the transcript stays bounded however long the window is used.
        internal static bool TranscriptStaysBounded()
        {
            MainWindow window = new MainWindow();
            for (int i = 0; i < MaxTranscriptMessages + 50; i++) window.AddMessage(i % 2 == 0, "message " + i);
            return window.transcript.Children.Count == MaxTranscriptMessages;
        }

        private void Send()
        {
            string value = commandBox.Text.Trim();
            if (value.Length == 0) return;
            commandBox.Clear();
            AddMessage(true, value);
            SafeCommand kind = CommandRouter.Classify(value);
            if (kind == SafeCommand.Help)
                AddMessage(false, "Available: status, version, doctor, devices, files, tasks, history, previews, control, stop control, revoke all, help. These operations are read-only, except three that only take authority away: previews sizes (prompts show sizes only), stop control (ends desktop control) and revoke all (with Windows Hello, invalidates every pending approval, desktop control and remote session lease). Task updates appear here as they happen. AI chat, voice, pairing, and execution are not connected.");
            else if (kind == SafeCommand.Devices)
                AddMessage(false, "Local computer: " + Environment.MachineName + ". Orcel runtime: " + (LocalHost.IsInstalled() ? "present (type status for its state)" : "not installed") + ". Remote devices: none (pairing is not integrated in this preview).");
            else if (kind == SafeCommand.Files)
                InspectFolder();
            else if (kind == SafeCommand.Tasks)
                ShowTasks();
            else if (kind == SafeCommand.History)
                ShowHistory();
            else if (kind == SafeCommand.PreviewsContent)
                AddMessage(false, "Not changed. This app only makes approval prompts show less. To show content previews again, run orcel approvals previews content in a terminal.");
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
            AddMessage(false, Progress(command));
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
                    CliResult result = LocalHost.Query(command, command == SafeCommand.Doctor ? DoctorTimeoutMs
                        : command == SafeCommand.RevokeAll ? RevokeAllTimeoutMs
                        : command == SafeCommand.Control || command == SafeCommand.StopControl ? ControlTimeoutMs
                        : QueryTimeoutMs);
                    if (CommandRouter.IsPreviewSetting(command)) return Interpret.PreviewsMessage(result);
                    if (command == SafeCommand.Control) return Interpret.ControlMessage(result);
                    if (command == SafeCommand.StopControl) return Interpret.StopControlMessage(result);
                    if (command == SafeCommand.RevokeAll) return Interpret.RevokeAllMessage(result);
                    return command == SafeCommand.Version ? Interpret.VersionMessage(result) : Interpret.DoctorMessage(result);
                });
                AddMessage(false, response);
            }
            catch (Exception)
            {
                AddMessage(false, command == SafeCommand.PreviewsSizes
                    ? "The approval preview setting failed unexpectedly. It may or may not have been saved; type previews to check."
                    : command == SafeCommand.StopControl
                    ? "Stopping desktop control failed unexpectedly. Run orcel full-control revoke in a terminal."
                    : command == SafeCommand.RevokeAll
                    ? "The emergency revoke failed unexpectedly. Run orcel emergency-revoke in a terminal."
                    : "The read-only runtime query failed unexpectedly. No action was performed.");
            }
        }

        private static string Progress(SafeCommand command)
        {
            if (command == SafeCommand.PreviewsSizes) return "Saving the approval preview setting...";
            if (command == SafeCommand.StopControl) return "Stopping desktop control...";
            if (command == SafeCommand.RevokeAll) return "Emergency revoke: confirm with Windows Hello when it asks. Every pending approval, desktop control and remote session lease will be invalidated.";
            return "Reading local runtime " + CommandRouter.CliArguments(command)[0] + "...";
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

        private async void ShowHistory()
        {
            AddMessage(false, "Reading the approval history from the local runtime...");
            try { AddMessage(false, await Task.Run(delegate { return ApprovalHistory.Read(); })); }
            catch (Exception) { AddMessage(false, "The read-only approval history query failed unexpectedly. No action was performed."); }
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
        private static Dictionary<string, object> OneTaskList()
        {
            return AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[{\"task_id\":\"rpt-9\"}]}}");
        }

        private static string TaskEvent(long seq, string state, string id)
        {
            return "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"event\":{\"seq\":" + seq + ",\"epoch\":\"e1\",\"run_id\":\"" + id + "\",\"step_id\":\"s1\",\"kind\":\"task.updated\",\"at_ms\":1,\"data\":{\"task_kind\":\"report\",\"state\":\"" + state + "\"}}}";
        }

        private static void WatcherSelfTest(Action<bool, string> expect)
        {
            const string Ack = "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":true,\"result\":{\"epoch\":\"e1\",\"head_seq\":5,\"after_seq\":0}}";
            bool finished;
            expect(AppApi.SubscribeFrame(0, null) == "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"method\":\"events.subscribe\",\"params\":{\"after_seq\":0}}\n", "a first subscription has no epoch");
            expect(AppApi.SubscribeFrame(7, "e1").Contains("\"params\":{\"after_seq\":7,\"epoch\":\"e1\"}"), "a cursor carries its epoch");

            WatchCursor cursor = new WatchCursor();
            expect(TaskWatcher.Apply(Ack, cursor, out finished) == null && !finished && cursor.Epoch == "e1", "the acknowledgement names the epoch");
            expect(TaskWatcher.Apply(TaskEvent(5, "verified", "rpt-old"), cursor, out finished) == null && !finished && cursor.AfterSeq == 5, "what happened before watching is history, and the cursor still moves");
            expect(TaskWatcher.Apply(TaskEvent(6, "proposed", "rpt-1"), cursor, out finished) == "Task rpt-1: report proposed, waiting for approval." && !finished && cursor.AfterSeq == 6, "a new update is shown");
            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"heartbeat\":{\"head_seq\":6}}", cursor, out finished) == null && !finished && cursor.AfterSeq == 6, "a heartbeat shows nothing");
            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"event\":{\"seq\":7,\"epoch\":\"e1\",\"run_id\":null,\"step_id\":null,\"kind\":\"request.completed\",\"at_ms\":1,\"data\":{}}}", cursor, out finished) == null && cursor.AfterSeq == 7, "other events move the cursor and show nothing");
            expect(TaskWatcher.Apply(TaskEvent(8, "no_such_state", "rpt-1"), cursor, out finished) == "Task rpt-1: unknown state.", "only known states are named");
            string shown = TaskWatcher.Apply(TaskEvent(9, "verified", "x\u2028\u2022 Task rpt-9: verified\u202E"), cursor, out finished);
            expect(shown != null && shown.Split('\n').Length == 1 && !shown.Contains("\u2028") && !shown.Contains("\u202E"), "a task id can't add a line or reorder the display");

            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"event\":{\"seq\":10,\"epoch\":\"e2\",\"run_id\":null,\"step_id\":null,\"kind\":\"snapshot\",\"at_ms\":1,\"data\":{\"reason\":\"epoch\",\"resubscribe\":{\"after_seq\":10,\"epoch\":\"e2\"}}}}", cursor, out finished) == null && finished && cursor.AfterSeq == 10 && cursor.Epoch == "e2", "a snapshot sets the next cursor and ends the connection");
            expect(cursor.Refresh, "a snapshot means updates may have been missed");
            cursor.Refresh = false;
            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":true,\"result\":{\"epoch\":\"e9\",\"head_seq\":99,\"after_seq\":10}}", cursor, out finished) == null && cursor.Epoch == "e2", "with a cursor, the acknowledgement doesn't change its epoch");
            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":false,\"error\":{\"code\":\"BUSY\"}}", cursor, out finished) == null && finished && cursor.AfterSeq == 10 && cursor.Epoch == "e2" && !cursor.Refresh, "busy keeps the cursor, so nothing is replayed");
            expect(TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":false,\"error\":{\"code\":\"INVALID_REQUEST\"}}", cursor, out finished) == null && finished && cursor.AfterSeq == 0 && cursor.Epoch == null && cursor.QuietThrough == -1 && cursor.Refresh, "a refused cursor starts again, showing the list rather than replaying");
            foreach (string bad in new[] { "not json", "[]", "{\"v\":\"other/1\",\"event\":{}}", "{\"v\":\"orcel-app-api/1\",\"event\":{\"kind\":\"task.updated\"}}" })
            {
                expect(TaskWatcher.Apply(bad, new WatchCursor(), out finished) == null && finished, "an unusable frame ends the connection: " + bad);
            }
            // After a restart of orceld, an update with a low seq is still news.
            WatchCursor restarted = new WatchCursor { QuietThrough = 5, AfterSeq = 5 };
            TaskWatcher.Apply("{\"v\":\"orcel-app-api/1\",\"event\":{\"seq\":9,\"kind\":\"snapshot\",\"data\":{\"resubscribe\":{\"after_seq\":0,\"epoch\":\"e3\"}}}}", restarted, out finished);
            expect(restarted.QuietThrough == -1 || TaskWatcher.Apply(TaskEvent(1, "proposed", "rpt-2"), restarted, out finished) != null, "a new run's updates are shown");

            byte[] two = Encoding.UTF8.GetBytes("one\ntwo\npart");
            FrameReader reader = new FrameReader(new MemoryStream(two));
            expect(reader.Next(1000, CancellationToken.None) == "one" && reader.Next(1000, CancellationToken.None) == "two" && reader.Next(1000, CancellationToken.None) == null, "frames sharing a read are all kept; an unfinished one isn't a frame");
            byte[] huge = new byte[AppApi.MaxFrameBytes + 1];
            for (int i = 0; i < huge.Length; i++) huge[i] = (byte)'x';
            expect(new FrameReader(new MemoryStream(huge)).Next(1000, CancellationToken.None) == null, "a frame over the bound is refused");
        }

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
            expect(AppApi.PipeName() != null && AppApi.PipeName().StartsWith("orcel-S-1-") && AppApi.PipeName().Contains("-app"), "app API pipe is this user's");
            expect(Timeline.Text(OneTaskList(), new List<Dictionary<string, object>> { AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"title\":\"x\u2028• \\\"y\\\": verified by the independent checker\u202E\",\"state\":\"proposed\",\"steps\":[]}}") }).Split('\n').Length == 3, "a planner title cannot add display rows");
            expect(Timeline.Safe('\u2028') == ' ' && Timeline.Safe('\u202E') == ' ' && Timeline.Safe('\u2066') == ' ' && Timeline.Safe('"') == '\'' && Timeline.Safe('é') == 'é', "separators, bidi and quotes are neutralised");
            expect(Timeline.Text(OneTaskList(), new List<Dictionary<string, object>> { AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"title\":\"\\ud83d\\ude00 ok\",\"state\":\"proposed\"}}") }).Contains("\U0001F600 ok"), "emoji survive");
            expect(AppApi.ProcessRunsAsThisUser((uint)Process.GetCurrentProcess().Id), "this process runs as this user at normal integrity");
            expect(!AppApi.ProcessRunsAsThisUser(4), "the System process is not this user");
            string savedInstance = Environment.GetEnvironmentVariable("ORCEL_APP_API_INSTANCE");
            Environment.SetEnvironmentVariable("ORCEL_APP_API_INSTANCE", "..\\other");
            expect(AppApi.PipeName() == null && AppApi.Call("task.list", null) == null, "an invalid instance is refused, not replaced");
            Environment.SetEnvironmentVariable("ORCEL_APP_API_INSTANCE", savedInstance);
            expect(AppApi.InstanceSuffix("ci-1") == "ci-1" && AppApi.InstanceSuffix("..\\x") == null && AppApi.InstanceSuffix("A") == null && AppApi.InstanceSuffix(new string('a', 33)) == null, "instance suffix is validated");
            bool refused = false;
            try { AppApi.RequestFrame("task.stop", "rpt-1"); } catch (ArgumentException) { refused = true; }
            expect(refused, "only read-only app API methods are sent");
            expect(AppApi.RequestFrame("task.list", null) == "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"method\":\"task.list\",\"params\":{}}\n", "task.list frame");
            expect(AppApi.RequestFrame("task.get", "rpt-a").Contains("\"params\":{\"task_id\":\"rpt-a\"}"), "task.get frame");
            expect(CommandRouter.Classify("previews") == SafeCommand.Previews && CommandRouter.Classify(" Previews Sizes ") == SafeCommand.PreviewsSizes && CommandRouter.Classify("previews content") == SafeCommand.PreviewsContent, "previews routes");
            expect(CommandRouter.Classify("previews all") == SafeCommand.Unsupported && CommandRouter.Classify("previews sizes; status") == SafeCommand.Unsupported, "only the two fixed choices are accepted");
            expect(string.Join(" ", CommandRouter.CliArguments(SafeCommand.PreviewsSizes)) == "approvals previews sizes --json" && string.Join(" ", CommandRouter.CliArguments(SafeCommand.Previews)) == "approvals previews --json", "previews passes fixed arguments only");
            expect(CommandRouter.CliArguments(SafeCommand.PreviewsContent) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.PreviewsContent), "the app never asks for content previews");
            expect(CommandRouter.CanInvokeInstalledHost(SafeCommand.Previews) && CommandRouter.CanInvokeInstalledHost(SafeCommand.PreviewsSizes), "previews and previews sizes reach the runtime");
            expect(CommandRouter.Classify("previews  sizes") == SafeCommand.Unsupported && CommandRouter.Classify("previews\tsizes") == SafeCommand.Unsupported && CommandRouter.Classify("previews \uFF53izes") == SafeCommand.Unsupported, "spacing and look-alike letters are refused");
            expect(Interpret.PreviewsMessage(new CliResult { TimedOut = true }).Contains("may or may not have been saved") && Interpret.PreviewsMessage(new CliResult { FailedToStart = true }).Contains("was not changed"), "a timeout and a failed start are reported honestly");
            expect(Interpret.PreviewsMessage(new CliResult { ExitCode = 2, Stdout = "{\n  \"ok\": false,\n  \"error\": {\n    \"kind\": \"state\",\n    \"message\": \"config.json has an unsupported schema\"\n  }\n}" }).StartsWith("The Orcel runtime answered the approval preview command with an error: config.json has an unsupported schema."), "the runtime's own refusal is shown");
            expect(Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\n  \"ok\": true,\n  \"approval_previews\": \"sizes\",\n  \"changed\": false\n}" }).StartsWith("Approval previews: sizes only.") && Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":false,\"approval_previews\":\"sizes\"}" }).Contains("did not report"), "pretty-printed output parses; ok must be true");
            expect(Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"approval_previews\":\"sizes\",\"changed\":true}" }).StartsWith("Approval previews: sizes only.") && Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"approval_previews\":\"sizes\",\"changed\":true}" }).Contains("Saved."), "a saved sizes choice is reported");
            expect(!Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"approval_previews\":\"content\",\"changed\":false}" }).Contains("Saved."), "an unchanged choice is not reported as saved");
            expect(Interpret.PreviewsMessage(new CliResult { ExitCode = 2, Stdout = "" }).Contains("did not report") && Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"approval_previews\":\"all\"}" }).Contains("did not report"), "an error or unknown answer is not a setting");
            expect(CommandRouter.Classify("control") == SafeCommand.Control && CommandRouter.Classify(" Stop Control ") == SafeCommand.StopControl && CommandRouter.Classify("revoke all") == SafeCommand.RevokeAll, "control commands route");
            expect(CommandRouter.Classify("grant control") == SafeCommand.Unsupported && CommandRouter.Classify("full-control grant") == SafeCommand.Unsupported && CommandRouter.Classify("stop  control") == SafeCommand.Unsupported, "nothing grants control, and only exact commands route");
            expect(string.Join(" ", CommandRouter.CliArguments(SafeCommand.Control)) == "full-control status --json" && string.Join(" ", CommandRouter.CliArguments(SafeCommand.StopControl)) == "full-control revoke --json" && string.Join(" ", CommandRouter.CliArguments(SafeCommand.RevokeAll)) == "emergency-revoke --json", "control commands pass fixed arguments only");
            expect(Interpret.StopControlMessage(new CliResult { ExitCode = 0, Stdout = "{\n  \"ok\": true,\n  \"revoked\": true,\n  \"authority_epoch\": 4\n}" }).StartsWith("Desktop control authority revoked.") && Interpret.StopControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"revoked\":false,\"authority_epoch\":null}" }).StartsWith("Desktop control was already off") && Interpret.StopControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true}" }).Contains("did not confirm"), "stop control reports what happened, and a missing answer isn't 'off'");
            expect(Interpret.StopControlMessage(new CliResult { TimedOut = true }).Contains("may or may not have stopped") && Interpret.StopControlMessage(new CliResult { ExitCode = 1, Stdout = "{\"ok\":false,\"error\":{\"kind\":\"state\",\"message\":\"the authority key is unreadable\"}}" }).StartsWith("Desktop control was NOT confirmed stopped: the authority key is unreadable."), "a stop that isn't confirmed says so");
            expect(Interpret.ControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"full_control\":{\"active\":true}}" }).StartsWith("Desktop control is ACTIVE") && Interpret.ControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"full_control\":{\"active\":false,\"reason\":\"no lease\\u202e\"}}" }) == "Desktop control is off (Safe): no lease.", "control status is read and escaped");
            expect(Interpret.RevokeAllMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"revoke\":{\"revoke_epoch\":2}}" }).StartsWith("Emergency revoke recorded") && Interpret.RevokeAllMessage(new CliResult { ExitCode = 1, Stdout = "{\"ok\":false,\"error\":{\"kind\":\"denied\",\"message\":\"Windows Hello was cancelled\"}}" }).StartsWith("The emergency revoke was not confirmed: Windows Hello was cancelled.") && Interpret.RevokeAllMessage(new CliResult { TimedOut = true }).Contains("may or may not have been recorded"), "revoke all never claims nothing happened after an error or a timeout");
            expect(Colors.Choose(true, "#000000", SystemColors.WindowTextBrush) == SystemColors.WindowTextBrush && ((SolidColorBrush)Colors.Choose(false, "#090D19", SystemColors.WindowTextBrush)).Color == Color.FromRgb(0x09, 0x0D, 0x19), "high contrast uses the system's colours, otherwise the dark palette");
            expect(MainWindow.Announcement("  short  ") == "short" && MainWindow.Announcement(new string('a', 500)).Length == MainWindow.MaxAnnouncedChars + 1, "screen-reader announcements are trimmed and bounded");
            expect(CommandRouter.Classify(" History ") == SafeCommand.History && CommandRouter.CliArguments(SafeCommand.History) == null, "history routes and never runs the CLI");
            expect(AppApi.RequestFrame("approval.history", null).Contains("\"method\":\"approval.history\",\"params\":{\"limit\":10}"), "approval.history frame");
            string history = ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"entries\":[{\"decision\":\"Approved\",\"approval_class\":\"SOFT\",\"workspace_id\":\"ws\\u2028x\",\"decided_at_ms\":1,\"consumed\":true,\"origin\":{\"kind\":\"remote\",\"provider\":\"tunnel\",\"device\":\"d\\u202e1\"}},{\"decision\":\"Denied\",\"approval_class\":\"STRONG\",\"workspace_id\":\"ws\",\"decided_at_ms\":2,\"origin\":null}]}}"));
            expect(history.Split('\n').Length == 4, "one line per decision; a field cannot add lines");
            expect(history.Contains("approved (SOFT), from REMOTE via tunnel, device d 1, workspace ws x, used") && history.Contains("denied (STRONG), from origin not recorded"), "history names decision, class, origin and use");
            expect(ApprovalHistory.When("999999999999999999") == "(time unknown)" && ApprovalHistory.When("x") == "(time unknown)", "an impossible time is not a crash");
            expect(ApprovalHistory.Text(null).StartsWith("Approval history unavailable") && ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"entries\":[]}}")) == "No approval decisions are recorded yet.", "empty and unavailable history say so");
            expect(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"ok\":false,\"error\":{\"code\":\"UNKNOWN_TASK\"}}") == null, "an error frame is not a result");
            WatcherSelfTest(expect);
            expect(AppApi.ParseReply("{\"v\":\"other/1\",\"ok\":true,\"result\":{}}") == null, "another protocol is refused");
            expect(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[]}}") != null, "an ok frame parses");
            expect(Timeline.Text(null, new List<Dictionary<string, object>>()).StartsWith("Task timeline unavailable"), "no answer is reported, not hidden");
            Dictionary<string, object> list = AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"max_tasks\":64,\"tasks\":[{\"task_id\":\"rpt-2\"},{\"task_id\":\"rpt-1\"}]}}");
            Dictionary<string, object> two = AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"task_id\":\"rpt-2\",\"title\":\"Q3\\nsummary\",\"state\":\"verified\",\"report\":{\"destination\":\"out/q3.md\"},\"steps\":[{\"kind\":\"observe\",\"outcome\":\"ok\"},{\"kind\":\"approval\",\"outcome\":\"approved\"},{\"kind\":\"check\",\"outcome\":\"pass\"}]}}");
            string timeline = Timeline.Text(list, new List<Dictionary<string, object>> { two, null });
            expect(timeline.Contains("• verified by the independent checker: \"Q3 summary\" → out/q3.md"), "a verified task is shown with its report, state first");
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
            expect(Interpret.StatusMessage(installed).Contains("is installed. ChatGPT tunnel not configured (optional)."), "status message is truthful");
            expect(Interpret.StatusMessage(installed).Contains("Next: add the folder"), "no workspace names the next step");
            expect(installed.Headline() == "Orcel runtime 0.2.0 • ChatGPT tunnel not configured (optional)", "headline names the tunnel");
            RuntimeStatus stale = Interpret.Status(new CliResult { ExitCode = 0, Stdout =
                "{\"installed\":\"0.2.0\",\"ok\":true,\"runtime\":{\"detail\":\"stale supervisor record\",\"state\":\"not_running\"},\"tunnel_configured\":true,\"workspaces\":1}" });
            expect(Interpret.StatusMessage(stale).Contains("ChatGPT tunnel not running (stale supervisor record).") && !Interpret.StatusMessage(stale).Contains("Next:"), "a configured tunnel shows its detail");
            RuntimeStatus failed = Interpret.Status(new CliResult { ExitCode = 7, Stdout =
                "{\"ok\":false,\"error\":{\"kind\":\"state\",\"message\":\"C:\\\\x\\\\supervisor.json is corrupt\"}}" });
            expect(failed.Availability == RuntimeAvailability.Failed && Interpret.StatusMessage(failed).Contains("supervisor.json is corrupt. No action"), "the runtime's own error is shown as a sentence");
            expect(Interpret.Plain("a\nb\u202Ec") == "a b c.", "runtime text can't start a line or reorder the display");
            expect(Interpret.Status(new CliResult { ExitCode = 7, Stdout = "{\"ok\":false,\"error\":{\"message\":\"\\n \"}}" }).Availability == RuntimeAvailability.Incompatible, "an empty error isn't shown as one");
            RuntimeStatus staleUnset = Interpret.Status(new CliResult { ExitCode = 0, Stdout =
                "{\"installed\":\"0.2.0\",\"ok\":true,\"runtime\":{\"detail\":\"stale supervisor record\",\"state\":\"not_running\"},\"tunnel_configured\":false,\"workspaces\":1}" });
            expect(Interpret.StatusMessage(staleUnset).Contains("ChatGPT tunnel not running (stale supervisor record)."), "a stale record isn't hidden as unconfigured");
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
            Console.WriteLine("Orcel command router (read-only plus the authority-reducing controls), runtime interpretation, bounded process and folder self-tests: PASS");
            return 0;
        }

        [STAThread]
        private static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--self-test") return SelfTest();
            if (args.Length == 1 && args[0] == "--ui-self-test")
            {
                MainWindow window = new MainWindow();
                if (window.Content == null) return 2;
                if (!MainWindow.TranscriptStaysBounded()) { Console.WriteLine("Orcel transcript bound: FAIL"); return 3; }
                Console.WriteLine("Orcel WPF layout construction and transcript bound: PASS");
                return 0;
            }
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
