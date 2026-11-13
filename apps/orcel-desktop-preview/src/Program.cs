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
    internal enum SafeCommand { Help, Status, Version, Doctor, Devices, Files, Tasks, History, Clients, Previews, PreviewsSizes, PreviewsContent, Control, StopControl, RevokeAll, Workspaces, Connect, Setup, Recovery, Settings, Unsupported }

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
            if (value == "clients") return SafeCommand.Clients;
            if (value == "setup") return SafeCommand.Setup;
            if (value == "settings") return SafeCommand.Settings;
            if (value == "recovery") return SafeCommand.Recovery;
            if (value == "previews") return SafeCommand.Previews;
            if (value == "previews sizes") return SafeCommand.PreviewsSizes;
            if (value == "previews content") return SafeCommand.PreviewsContent;
            if (value == "control") return SafeCommand.Control;
            if (value == "stop control") return SafeCommand.StopControl;
            if (value == "revoke all") return SafeCommand.RevokeAll;
            if (value == "workspaces") return SafeCommand.Workspaces;
            if (value == "connect") return SafeCommand.Connect;
            return SafeCommand.Unsupported;
        }

        internal static bool CanInvokeInstalledHost(SafeCommand command)
        {
            return command == SafeCommand.Status || command == SafeCommand.Version || command == SafeCommand.Doctor
                || IsPreviewSetting(command) || IsControl(command) || command == SafeCommand.Workspaces;
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
            if (command == SafeCommand.Workspaces) return new[] { "workspace", "list", "--json" };
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
        internal static readonly string[] Methods = { "task.list", "task.get", "events.subscribe", "approval.history", "clients.list" };

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
            return NewestIds(list, MaxShownTasks);
        }

        internal static List<string> NewestIds(Dictionary<string, object> list, int max)
        {
            List<string> ids = new List<string>();
            object tasks;
            if (list == null || !list.TryGetValue("tasks", out tasks) || !(tasks is IEnumerable)) return ids;
            foreach (object task in (IEnumerable)tasks)
            {
                string id = Field(task as Dictionary<string, object>, "task_id");
                if (id != null && ids.Count < max) ids.Add(id);
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

    /// What Orcel found after it restarted: when orceld exits while a report is being written,
    /// the next orceld checks the destination and records a `reconcile` step on the task. This
    /// says what each check found, in plain words. It reads only and never retries anything.
    internal static class Recovery
    {
        internal const int MaxScanned = 10;

        private static string Field(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : null;
        }

        /// The outcome of a task's last reconcile step, or null when it has none.
        internal static string LastReconcile(Dictionary<string, object> task)
        {
            object steps;
            string outcome = null;
            if (task == null || !task.TryGetValue("steps", out steps) || !(steps is IEnumerable) || steps is string) return null;
            foreach (object step in (IEnumerable)steps)
            {
                Dictionary<string, object> map = step as Dictionary<string, object>;
                if (Field(map, "kind") == "reconcile") outcome = Field(map, "outcome") ?? "";
            }
            return outcome;
        }

        internal static string Meaning(string outcome)
        {
            switch (outcome)
            {
                case "verified": return "the report is there and the independent checker passes it.";
                case "nothing_written": return "nothing was written. Ask your client to run it again if you still want it.";
                case "unknown": return "a file is there, or couldn't be read, and it doesn't check, so Orcel can't tell what happened and won't retry. Check the destination yourself before using it.";
                default: return "the check gave an answer this app doesn't know. Type tasks for the details.";
            }
        }

        internal static string Text(Dictionary<string, object> list, IList<Dictionary<string, object>> tasks)
        {
            if (list == null)
                return "Recovery check unavailable: this user's app API pipe did not answer, gave an unusable answer, or is not served by this user at normal integrity (the runtime may not be running). Nothing was changed.";
            StringBuilder text = new StringBuilder();
            int found = 0, unknown = 0, unreadable = 0;
            foreach (Dictionary<string, object> task in tasks)
            {
                if (task == null) { unreadable++; continue; }
                string outcome = LastReconcile(task);
                if (outcome == null) continue;
                found++;
                if (outcome != "verified" && outcome != "nothing_written") unknown++;
                text.Append("\n• \"" + Timeline.ShownText(Field(task, "title")) + "\"");
                object proposal;
                if (task.TryGetValue("proposal", out proposal) && proposal is Dictionary<string, object>)
                    text.Append(" → " + Timeline.ShownText(Field((Dictionary<string, object>)proposal, "destination")));
                text.Append(": " + Meaning(outcome));
            }
            // A task whose details didn't come back may be one that was checked, so it is never
            // counted as "not interrupted".
            string missed = unreadable == 0 ? "" : "\n" + unreadable + (unreadable == 1 ? " task's details" : " tasks' details") + " couldn't be read just now, so this may be incomplete; type recovery again.";
            if (found == 0)
                return (unreadable == 0
                    ? "No report was interrupted by an Orcel restart among the newest " + MaxScanned + " tasks. Orcel checks any report it was writing when it stopped the next time it starts."
                    : "No interrupted report was found among the tasks that could be read.") + missed;
            string head = "Reports Orcel was writing when it stopped, as it found them the next time it started (newest first; titles and paths come from the planner and are not verified):";
            if (unknown > 0) head = unknown + (unknown == 1 ? " report needs" : " reports need") + " your attention. " + head;
            return head + text.ToString() + missed + "\nThis app reads only; it never retries or deletes anything.";
        }

        internal static string Read()
        {
            Dictionary<string, object> list = AppApi.Call("task.list", null);
            List<Dictionary<string, object>> details = new List<Dictionary<string, object>>();
            foreach (string id in Timeline.NewestIds(list, MaxScanned)) details.Add(AppApi.Call("task.get", id));
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
            string ledger = Field(result, "ledger");
            // No field (an older runtime) says nothing; anything but "verified" is a caveat, so a
            // state this app doesn't know is never shown as checked.
            string caveat = ledger == null || ledger == "verified"
                ? null
                : ledger == "unverifiable"
                ? "The approval history failed its integrity check, so this is the last checked view and may miss recent decisions. Run orcel approvals in a terminal for details."
                : "The approval history couldn't be read just now (busy or unavailable), so this is the last checked view and may miss recent decisions.";
            StringBuilder text = new StringBuilder(caveat == null ? "Recent approval decisions, newest first:" : caveat + "\nRecent approval decisions, newest first:");
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
            if (shown == 0) return caveat == null ? "No approval decisions are recorded yet." : caveat + " No decisions were in that view.";
            text.Append("\nThis app reads the history only; approvals are answered in the system's own prompt.");
            return text.ToString();
        }

        internal static string Read()
        {
            return Text(AppApi.Call("approval.history", null));
        }
    }

    /// The local AI clients connected now, as orceld records them: each MCP session's own
    /// orceld writes a record when its client says hello and removes it when the session ends.
    /// Names are what each client said about itself. It reads only; it can't disconnect anyone.
    internal static class ConnectedClients
    {
        internal const int MaxShown = 10;

        private static string Field(Dictionary<string, object> map, string key)
        {
            object value;
            return map != null && map.TryGetValue(key, out value) && value != null ? Convert.ToString(value) : null;
        }

        internal static string Text(Dictionary<string, object> result)
        {
            if (result == null) return "Connected clients unavailable: the local runtime did not answer, or this version of it can't list clients.";
            if (Field(result, "registry") != "ok") return "Connected clients unavailable: the local runtime has no private folder for session records.";
            object clients;
            if (!result.TryGetValue("clients", out clients) || !(clients is IEnumerable) || clients is string) return "Connected clients unavailable: the answer had no clients.";
            StringBuilder text = new StringBuilder("AI clients connected now, newest first. Names are what each client reported and are not verified:");
            int shown = 0;
            foreach (object item in (IEnumerable)clients)
            {
                Dictionary<string, object> entry = item as Dictionary<string, object>;
                if (entry == null) continue;
                if (shown++ >= MaxShown) break;
                Dictionary<string, object> client = entry.ContainsKey("client") ? entry["client"] as Dictionary<string, object> : null;
                string name = Field(client, "name");
                string version = Field(client, "version");
                string line = (name == null ? "an unnamed client" : Timeline.ShownText(name))
                    + (version == null ? "" : " " + Timeline.ShownText(version))
                    + ", over " + Timeline.ShownText(Field(entry, "transport") ?? "unknown")
                    + ", since " + ApprovalHistory.When(Field(entry, "started_at_ms"))
                    + (Field(entry, "workspace_id") == null ? "" : ", workspace " + Timeline.ShownText(Field(entry, "workspace_id")));
                text.Append("\n• ").Append(line);
            }
            if (shown == 0) return "No AI clients are connected right now. A client running an older Orcel, or one that started before it was updated, isn't listed.";
            if (Field(result, "truncated") == "True" || shown > MaxShown) text.Append("\nMore are connected than shown here.");
            text.Append("\nThis app only shows them; it can't disconnect a client. Close the client to end its session.");
            return text.ToString();
        }

        internal static string Read()
        {
            return Text(AppApi.Call("clients.list", null));
        }
    }

    /// A guided first run: what is done and what to do next, from what this computer shows (is
    /// Orcel installed, is a client connected). It reads only; each step is the person's to take.
    internal static class SetupGuide
    {
        internal enum ClientState { Connected, None, Unknown }

        /// Whether any client is connected, from a `clients.list` answer.
        internal static ClientState Clients(Dictionary<string, object> result, out int count)
        {
            count = 0;
            object registry, clients;
            if (result == null || !result.TryGetValue("registry", out registry) || !"ok".Equals(registry)) return ClientState.Unknown;
            if (!result.TryGetValue("clients", out clients) || !(clients is IEnumerable) || clients is string) return ClientState.Unknown;
            foreach (object item in (IEnumerable)clients) if (item is Dictionary<string, object>) count++;
            return count > 0 ? ClientState.Connected : ClientState.None;
        }

        /// True when every step this app can check is done.
        internal static bool Complete(bool installed, ClientState clients)
        {
            return installed && clients == ClientState.Connected;
        }

        /// Whether the checklist shows by itself at launch: only while Orcel isn't installed.
        /// After that a closed client or a runtime that isn't serving looks the same as one never
        /// set up, so it would show at every launch; `setup` shows it on request.
        internal static bool ShowAtLaunch(bool installed)
        {
            return !installed;
        }

        /// How many entries a read-only answer lists under `key` (`entries` of
        /// `approval.history`, `tasks` of `task.list`), or null without a usable answer.
        internal static int? Listed(Dictionary<string, object> result, string key)
        {
            object items;
            if (result == null || !result.TryGetValue(key, out items) || !(items is IEnumerable) || items is string) return null;
            int count = 0;
            foreach (object item in (IEnumerable)items) if (item is Dictionary<string, object>) count++;
            return count;
        }

        /// Whether Orcel has done anything yet: a recorded approval decision or a report task
        /// says so. Null when neither could be read.
        internal static bool? Tried(int? decisions, int? tasks)
        {
            if ((decisions ?? 0) > 0 || (tasks ?? 0) > 0) return true;
            if (decisions == null && tasks == null) return null;
            return false;
        }

        internal static string Text(bool installed, ClientState clients, int count)
        {
            return Text(installed, clients, count, null, null);
        }

        /// `workspaces` is how many folders Orcel may use and `tried` whether it has done
        /// anything yet; null means this app couldn't tell, and the step says so.
        internal static string Text(bool installed, ClientState clients, int count, int? workspaces, bool? tried)
        {
            StringBuilder text = new StringBuilder("Getting started with Orcel:");
            text.Append(installed
                ? "\n1. Install Orcel for this Windows user: done."
                : "\n1. Install Orcel for this Windows user: not yet. In a terminal in the extracted release folder, run .\\orcel.exe install, then reopen this app.");
            if (!installed)
                text.Append("\n2. Connect an AI client: after installing, type connect for the setup to paste into Claude Desktop, Claude Code, Codex or another client.");
            else if (clients == ClientState.Connected)
                text.Append("\n2. Connect an AI client: done, " + count + (count == 1 ? " client is" : " clients are") + " connected now (type clients to see them).");
            else if (clients == ClientState.None)
                text.Append("\n2. Connect an AI client: none is connected now. Type connect for the setup to paste into your client, then restart the client.");
            else
                text.Append("\n2. Connect an AI client: this app couldn't check. Type connect for the setup to paste into your client, then restart the client.");
            const string addFolder = "in a terminal, run orcel workspace add <id> <folder> (type workspaces to see them; this app never adds folders).";
            if (installed && workspaces > 0)
                text.Append("\n3. Choose a folder Orcel may work in: done, " + workspaces + (workspaces == 1 ? " folder is" : " folders are") + " set up (type workspaces to see them).");
            else if (installed && workspaces == 0)
                text.Append("\n3. Choose a folder Orcel may work in: none yet; " + addFolder);
            else
                text.Append("\n3. Choose a folder Orcel may work in: " + addFolder);
            const string tryIt = "ask your client to do something in that folder. When an action needs your approval, Orcel asks in its own prompt; type history to see the decisions.";
            if (installed && tried == true)
                text.Append("\n4. Try it: done, Orcel has recorded work (type history or tasks to see it).");
            else
                text.Append("\n4. Try it: " + tryIt);
            text.Append("\nAt any time: previews sizes hides content in approval prompts, and stop control or revoke all take authority away.");
            string next = !installed ? "install Orcel (step 1)."
                : clients != ClientState.Connected ? "connect a client (step 2)."
                : workspaces == 0 ? "choose a folder (step 3)."
                : workspaces == null ? "choose a folder (step 3) if you haven't, then try it (step 4)."
                : tried == true ? "nothing; Orcel is set up. Type help for what this app shows."
                : "try it (step 4).";
            text.Append("\nNext: " + next);
            return text.ToString();
        }

        /// The checklist. At launch (`launch`) it is built only when it shows then, which is
        /// before anything is installed, so no runtime is asked; null means it doesn't show.
        internal static string Read(bool launch)
        {
            bool installed = LocalHost.IsInstalled();
            if (launch && !ShowAtLaunch(installed)) return null;
            int count = 0;
            ClientState clients = installed ? Clients(AppApi.Call("clients.list", null), out count) : ClientState.Unknown;
            if (!installed) return Text(installed, clients, count);
            // Read only: the same fixed `workspace list` the workspaces command runs, and the
            // app API's approval history and task list.
            int? workspaces = null;
            try { workspaces = Interpret.WorkspaceCount(LocalHost.Query(SafeCommand.Workspaces, WorkspacesTimeoutMs)); }
            catch (Exception) { workspaces = null; }
            bool? tried = Tried(Listed(AppApi.Call("approval.history", null), "entries"), Listed(AppApi.Call("task.list", null), "tasks"));
            return Text(installed, clients, count, workspaces, tried);
        }

        /// Listing workspaces asks the runtime about each one's trust; the guided start waits
        /// less than the workspaces command does.
        private const int WorkspacesTimeoutMs = 30000;
    }

    /// The settings Orcel has now, in one place, each with where it is changed. It reads only,
    /// through the same fixed queries `previews`, `control` and `workspaces` run and the app
    /// API's `clients.list`; the one change the app makes itself (sizes-only previews) stays its
    /// own command, and everything that grants anything stays in a terminal.
    internal static class SettingsView
    {
        internal enum PreviewsState { SizesOnly, Content, Unknown }
        internal enum ControlState { Active, Off, Unknown }

        /// The setting a previews reply reports; anything else (no answer, an error) is unknown.
        internal static PreviewsState PreviewsOf(string reply)
        {
            if (reply == null) return PreviewsState.Unknown;
            if (reply.StartsWith("Approval previews: sizes only", StringComparison.Ordinal)) return PreviewsState.SizesOnly;
            if (reply.StartsWith("Approval previews: a short preview", StringComparison.Ordinal)) return PreviewsState.Content;
            return PreviewsState.Unknown;
        }

        /// The state a control status reply reports; anything else is unknown.
        internal static ControlState ControlOf(string reply)
        {
            if (reply == null) return ControlState.Unknown;
            if (reply.StartsWith("Desktop control is ACTIVE", StringComparison.Ordinal)) return ControlState.Active;
            if (reply.StartsWith("Desktop control is off", StringComparison.Ordinal)) return ControlState.Off;
            return ControlState.Unknown;
        }

        /// Read-only wording: what each setting is now and where it is changed, never the wording
        /// of a change.
        internal static string Text(PreviewsState previews, ControlState control, int? workspaces, SetupGuide.ClientState clients, int clientCount)
        {
            StringBuilder text = new StringBuilder("Orcel settings (this app only reads them; where each is changed is named):");
            text.Append("\n• ").Append(previews == PreviewsState.SizesOnly
                ? "Approval previews: sizes only, so prompts never show content. Content previews are turned back on in a terminal: orcel approvals previews content."
                : previews == PreviewsState.Content
                ? "Approval previews: a short preview, hidden when it looks like a password, key or token. To show sizes only, type previews sizes."
                : "Approval previews: couldn't check. Type previews to try again.");
            text.Append("\n• ").Append(control == ControlState.Active
                ? "Desktop control: ACTIVE, so Orcel may type and click until its lease ends. Type stop control to end it now."
                : control == ControlState.Off
                ? "Desktop control: off. Granting it stays in a terminal (orcel full-control grant), behind Windows Hello."
                : "Desktop control: couldn't check. Type control to try again.");
            text.Append("\n• Folders Orcel may use: ")
                .Append(workspaces == null ? "couldn't check." : workspaces + ".")
                .Append(" Type workspaces to see them; add or remove them with orcel workspace in a terminal.");
            text.Append("\n• AI clients connected now: ")
                .Append(clients == SetupGuide.ClientState.Unknown ? "couldn't check." : clientCount + ".")
                .Append(" Type clients to see them, or connect for the setup to paste into a client.");
            text.Append("\n• Emergency: revoke all invalidates every pending approval, desktop control and remote session lease, with Windows Hello.");
            return text.ToString();
        }

        internal static string Read()
        {
            if (!LocalHost.IsInstalled())
                return "Orcel isn't installed for this Windows user yet, so it has no settings to show. Type setup for the first steps.";
            PreviewsState previews;
            ControlState control;
            int? workspaces;
            try { previews = PreviewsOf(Interpret.PreviewsMessage(LocalHost.Query(SafeCommand.Previews, QueryTimeoutMs))); }
            catch (Exception) { previews = PreviewsState.Unknown; }
            try { control = ControlOf(Interpret.ControlMessage(LocalHost.Query(SafeCommand.Control, QueryTimeoutMs))); }
            catch (Exception) { control = ControlState.Unknown; }
            try { workspaces = Interpret.WorkspaceCount(LocalHost.Query(SafeCommand.Workspaces, WorkspacesTimeoutMs)); }
            catch (Exception) { workspaces = null; }
            int count;
            SetupGuide.ClientState clients = SetupGuide.Clients(AppApi.Call("clients.list", null), out count);
            return Text(previews, control, workspaces, clients, count);
        }

        private const int QueryTimeoutMs = 15000;
        private const int WorkspacesTimeoutMs = 30000;
    }

    /// How to connect a local AI client: the setup to paste into the client, with this
    /// install's exact path. The app shows it and edits no client's configuration.
    internal static class ConnectGuide
    {
        /// A path as a PowerShell single-quoted string's contents: nothing inside it expands
        /// (no `$`, backtick or `$(...)`). PowerShell ends such a string at any of its single
        /// quotes, the ASCII one and the curly U+2018 to U+201B, so each is doubled.
        internal static string PowerShellPath(string path)
        {
            StringBuilder text = new StringBuilder();
            foreach (char c in path ?? "")
            {
                text.Append(c);
                if (c == '\'' || c == '\u2018' || c == '\u2019' || c == '\u201A' || c == '\u201B') text.Append(c);
            }
            return text.ToString();
        }

        /// A Windows path as a JSON string's contents: backslashes and quotes escaped.
        internal static string JsonPath(string path)
        {
            return (path ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        /// What a screen reader hears for the guide: where to find it, not its punctuation.
        internal const string Announcement = "Setup for Claude Desktop, Claude Code, Codex and other clients is in the text box below, to select and copy.";

        internal static string Text(string cli, bool installed)
        {
            if (!installed)
                return "Orcel isn't installed for this Windows user yet, so there is nothing to connect. Install it first (in a terminal in the extracted release folder, run .\\orcel.exe install), then type connect again.";
            string json = JsonPath(cli);
            return "To connect a local AI client, add Orcel as a stdio MCP server, then restart the client. Copy what you need from here.\n\n"
                + "Claude Desktop (claude_desktop_config.json; if it already has mcpServers, add only the orcel entry inside it):\n"
                + "{ \"mcpServers\": { \"orcel\": { \"command\": \"" + json + "\", \"args\": [\"mcp\", \"stdio\"] } } }\n\n"
                + "Claude Code, in PowerShell (for every folder you use it in):\n"
                + "claude mcp add --scope user orcel -- '" + PowerShellPath(cli) + "' mcp stdio\n\n"
                + "Codex (~/.codex/config.toml):\n"
                + "[mcp_servers.orcel]\ncommand = \"" + json + "\"\nargs = [\"mcp\", \"stdio\"]\nstartup_timeout_sec = 20\ntool_timeout_sec = 60\n\n"
                + "Other clients: transport stdio, command " + cli + ", arguments mcp stdio.\n\n"
                + "Every change a client asks Orcel to make still needs your approval in Orcel's own prompt. This app doesn't edit any client's settings.";
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

        internal const int MaxShownWorkspaces = 20;

        /// `orcel workspace list --json`: the folders Orcel may use, with their trust. The app
        /// shows them and never adds one: adding a folder grants Orcel access, so it stays in a
        /// terminal.
        internal static string WorkspacesMessage(CliResult result)
        {
            if (result.FailedToStart) return "The Orcel runtime could not be started to list workspaces.";
            if (result.TimedOut) return "The Orcel runtime did not list workspaces in time. It may be waiting for another Orcel command, such as a grant waiting for Windows Hello; try again, or run orcel workspace list in a terminal.";
            Dictionary<string, object> answer = Parse(result.Stdout);
            string refusal = Refusal(result, answer);
            if (refusal != null) return "The Orcel runtime could not list workspaces: " + refusal;
            Dictionary<string, object> json = Ok(result, answer);
            object raw;
            object[] rows = json != null && json.TryGetValue("workspaces", out raw) ? raw as object[] : null;
            if (rows == null) return "The installed Orcel runtime did not list workspaces in a form this app understands.";
            foreach (object item in rows)
                if (!(item is Dictionary<string, object>)) return "The installed Orcel runtime did not list workspaces in a form this app understands.";
            StringBuilder text = new StringBuilder("Folders Orcel may use:");
            int shown = 0, total = 0;
            foreach (object item in rows)
            {
                Dictionary<string, object> row = item as Dictionary<string, object>;
                if (row == null) continue;
                total++;
                if (shown >= MaxShownWorkspaces) continue;
                shown++;
                object trustRaw;
                Dictionary<string, object> trust = row.TryGetValue("trust", out trustRaw) ? trustRaw as Dictionary<string, object> : null;
                object trusted = null;
                if (trust != null) trust.TryGetValue("trusted", out trusted);
                string state = true.Equals(trusted) ? "trusted for STRONG operations" : false.Equals(trusted) ? "not trusted for STRONG operations" : "trust unknown";
                text.Append("\n• ").Append(Timeline.ShownText(Text(row, "id"))).Append(" (").Append(state).Append("): ").Append(Timeline.ShownText(Text(row, "root")));
            }
            if (total == 0)
                return "No workspaces are configured, so Orcel can't use any folder yet. To add one, run orcel workspace add <id> <folder> in a terminal. This app never adds folders.";
            if (total > shown) text.Append("\n(" + (total - shown) + " more not shown; run orcel workspace list in a terminal)");
            text.Append("\nTo add or remove a folder, or change its trust, use orcel workspace in a terminal. This app never grants a folder.");
            return text.ToString();
        }

        /// How many workspaces `orcel workspace list --json` reports, or null when it gave no
        /// usable answer.
        internal static int? WorkspaceCount(CliResult result)
        {
            if (result == null || result.FailedToStart || result.TimedOut) return null;
            Dictionary<string, object> answer = Parse(result.Stdout);
            if (Refusal(result, answer) != null) return null;
            Dictionary<string, object> json = Ok(result, answer);
            object raw;
            object[] rows = json != null && json.TryGetValue("workspaces", out raw) ? raw as object[] : null;
            if (rows == null) return null;
            int count = 0;
            foreach (object item in rows)
            {
                if (!(item is Dictionary<string, object>)) return null;
                count++;
            }
            return count;
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
        /// The stop button: a warm red with dark text, so it never looks like the accent
        /// buttons beside it. In high contrast it is the window's colours with a heavy border,
        /// where the accent buttons are filled with the highlight colour.
        internal static Brush Stop = Choose(HighContrast, "#F49A93", SystemColors.WindowBrush);
        internal static Brush OnStop = Choose(HighContrast, "#090D19", SystemColors.WindowTextBrush);
        internal static Brush StopBorder = Choose(HighContrast, "#FFD2CE", SystemColors.WindowTextBrush);

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
        /// Desktop control commands no longer wait for the runtime's lifecycle lock, but a
        /// revoke may wait up to 5 s for the authority store's own lock; this leaves room for an
        /// older runtime, which waited up to 60 s for the lifecycle lock.
        private const int ControlTimeoutMs = 70000;
        /// Listing workspaces asks the runtime about each one's trust, up to 20 s each.
        private const int WorkspacesTimeoutMs = 90000;
        /// Commands that change something and are still running.
        private readonly HashSet<SafeCommand> running = new HashSet<SafeCommand>();
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
            Loaded += delegate { RefreshHost(); commandBox.Focus(); WatchTasks(); ShowSetup(true); };
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

        internal static System.Windows.Controls.Button ActionButton(string title, bool enabled, string automationId)
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

        /// A button that only takes authority away, styled apart from the others: its own
        /// colour, a border and a stop mark. Its accessible name stays the plain title.
        internal static System.Windows.Controls.Button StopButton(string title, string automationId)
        {
            System.Windows.Controls.Button button = ActionButton(title, true, automationId);
            button.Content = "■  " + title;
            button.Background = Colors.Stop;
            button.Foreground = Colors.OnStop;
            button.BorderBrush = Colors.StopBorder;
            button.BorderThickness = new Thickness(2);
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
            ConfigureAnnouncer(announcer);
            center.Children.Add(announcer);
            Border transcriptCard = Card(conversation, Colors.Sidebar, new Thickness(14));
            Grid.SetRow(transcriptCard, 1);
            center.Children.Add(transcriptCard);
            AddMessage(false, "Welcome to Orcel. Type setup for a guided start, connect to set up an AI client, or help to see the commands, such as status, tasks, history, control or stop control. Other requests are not executed or sent anywhere.");

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
            commandBox.ToolTip = "Commands: help, setup, settings, status, version, doctor, devices, files, tasks, recovery, history, clients, workspaces, connect, previews, control, stop control, revoke all";
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
            System.Windows.Controls.Button stopControl = StopButton("Stop desktop control", "StopControlButton");
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
            AddMessage(fromUser, message, false);
        }

        /// `selectable` shows the reply in a read-only text box, so it can be selected and
        /// copied, for setup text a person pastes elsewhere.
        private void AddMessage(bool fromUser, string message, bool selectable)
        {
            messages++;
            StackPanel item = new StackPanel { Margin = new Thickness(0, 0, 0, 12) };
            item.HorizontalAlignment = fromUser ? HorizontalAlignment.Right : HorizontalAlignment.Left;
            TextBlock who = Text(fromUser ? "YOU" : "ORCEL · LOCAL", 10, Colors.Muted, true);
            who.Margin = new Thickness(4, 0, 4, 5);
            item.Children.Add(who);
            FrameworkElement body;
            if (selectable)
            {
                System.Windows.Controls.TextBox box = new System.Windows.Controls.TextBox {
                    Text = message, IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
                    FontSize = 13, Foreground = Colors.Ink, Background = Colors.Surface,
                    // A border, so keyboard focus on the box is visible.
                    BorderThickness = new Thickness(1), BorderBrush = Colors.Border,
                    FontFamily = new FontFamily("Consolas")
                };
                AutomationProperties.SetName(box, "Setup to copy");
                // The box's own scroller would swallow the wheel; the transcript scrolls instead.
                box.PreviewMouseWheel += delegate(object sender, System.Windows.Input.MouseWheelEventArgs e) {
                    e.Handled = true;
                    conversation.ScrollToVerticalOffset(conversation.VerticalOffset - e.Delta / 3.0);
                };
                body = box;
            }
            else
            {
                body = Text(message, 13, Colors.Ink, false);
            }
            AutomationProperties.SetAutomationId(body, "Message" + messages);
            Border bubble = Card(body, fromUser ? Colors.Bubble : Colors.Surface, new Thickness(13, 10, 13, 10));
            bubble.MaxWidth = 560;
            item.Children.Add(bubble);
            transcript.Children.Add(item);
            while (transcript.Children.Count > MaxTranscriptMessages) transcript.Children.RemoveAt(0);
            conversation.ScrollToEnd();
            if (!fromUser) Announce(selectable ? ConnectGuide.Announcement : message);
        }

        /// The live region's setup: polite, out of the way, never focused or clicked.
        internal static void ConfigureAnnouncer(TextBlock announcer)
        {
            AutomationProperties.SetAutomationId(announcer, "Announcement");
            AutomationProperties.SetLiveSetting(announcer, AutomationLiveSetting.Polite);
            announcer.FontSize = 1;
            announcer.Height = 1;
            announcer.VerticalAlignment = VerticalAlignment.Top;
            announcer.Opacity = 0;
            announcer.IsHitTestVisible = false;
            announcer.Focusable = false;
        }

        /// What a screen reader hears for a reply: the reply, cut at MaxAnnouncedChars.
        internal static string Announcement(string message)
        {
            string text = (message ?? "").Trim();
            if (text.Length <= MaxAnnouncedChars) return text;
            int cut = MaxAnnouncedChars;
            // Never split a surrogate pair.
            if (char.IsHighSurrogate(text[cut - 1])) cut--;
            return text.Substring(0, cut) + "…";
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
                AddMessage(false, "Available: setup, settings, status, version, doctor, devices, files, tasks, recovery, history, clients, workspaces, connect, previews, control, stop control, revoke all, help. These operations are read-only, except three that only take authority away: previews sizes (prompts show sizes only), stop control (ends desktop control) and revoke all (with Windows Hello, invalidates every pending approval, desktop control and remote session lease). Task updates appear here as they happen. AI chat, voice, pairing, and execution are not connected.");
            else if (kind == SafeCommand.Devices)
                AddMessage(false, "Local computer: " + Environment.MachineName + ". Orcel runtime: " + (LocalHost.IsInstalled() ? "present (type status for its state)" : "not installed") + ". Remote devices: none (pairing is not integrated in this preview).");
            else if (kind == SafeCommand.Files)
                InspectFolder();
            else if (kind == SafeCommand.Tasks)
                ShowTasks();
            else if (kind == SafeCommand.History)
                ShowHistory();
            else if (kind == SafeCommand.Clients)
                ShowClients();
            else if (kind == SafeCommand.Settings)
                ShowSettings();
            else if (kind == SafeCommand.Setup)
                ShowSetup(false);
            else if (kind == SafeCommand.Recovery)
                ShowRecovery();
            else if (kind == SafeCommand.Connect)
            {
                // Only the setup itself goes in the copyable box; the install instruction is an
                // ordinary reply, read out as it is.
                bool installed = LocalHost.IsInstalled();
                AddMessage(false, ConnectGuide.Text(LocalHost.PathToCompatCli(), installed), installed);
            }
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
            // One run at a time for the commands that change something, and for the workspace
            // list, which holds the runtime's lock: a double click or a repeated command doesn't
            // start a second revoke, a second Windows Hello prompt or a second wait on the lock.
            bool guarded = command == SafeCommand.StopControl || command == SafeCommand.RevokeAll || command == SafeCommand.PreviewsSizes
                || command == SafeCommand.Workspaces;
            // setup lists workspaces too, so the two share one wait on the runtime's lock.
            if (guarded && (running.Contains(command) || (command == SafeCommand.Workspaces && (running.Contains(SafeCommand.Setup) || running.Contains(SafeCommand.Settings)))))
            {
                AddMessage(false, "That is already running; wait for its answer.");
                return;
            }
            try
            {
                if (guarded) running.Add(command);
                AddMessage(false, Progress(command));
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
                        : command == SafeCommand.Workspaces ? WorkspacesTimeoutMs
                        : QueryTimeoutMs);
                    if (command == SafeCommand.Workspaces) return Interpret.WorkspacesMessage(result);
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
            finally
            {
                running.Remove(command);
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

        /// Lists workspaces too, so it shares the workspaces command's one-at-a-time guard.
        private async void ShowSettings()
        {
            if (running.Contains(SafeCommand.Settings) || running.Contains(SafeCommand.Setup) || running.Contains(SafeCommand.Workspaces))
            {
                AddMessage(false, "That is already running; wait for its answer.");
                return;
            }
            running.Add(SafeCommand.Settings);
            AddMessage(false, "Reading Orcel's settings...");
            try { AddMessage(false, await Task.Run(delegate { return SettingsView.Read(); })); }
            catch (Exception) { AddMessage(false, "The read-only settings check failed unexpectedly. No action was performed."); }
            finally { running.Remove(SafeCommand.Settings); }
        }

        /// At launch the checklist appears only while Orcel isn't installed.
        private async void ShowSetup(bool launch)
        {
            // On request it lists workspaces, which waits on the runtime's lock: one at a time,
            // and never alongside the workspaces command. At launch nothing is read.
            if (!launch)
            {
                if (running.Contains(SafeCommand.Setup) || running.Contains(SafeCommand.Workspaces) || running.Contains(SafeCommand.Settings))
                {
                    AddMessage(false, "That is already running; wait for its answer.");
                    return;
                }
                running.Add(SafeCommand.Setup);
                AddMessage(false, "Checking what is set up...");
            }
            try
            {
                string text = await Task.Run(delegate { return SetupGuide.Read(launch); });
                if (text != null) AddMessage(false, text);
            }
            catch (Exception)
            {
                if (!launch) AddMessage(false, "The read-only setup check failed unexpectedly. No action was performed.");
            }
            finally
            {
                if (!launch) running.Remove(SafeCommand.Setup);
            }
        }

        private async void ShowRecovery()
        {
            AddMessage(false, "Checking what Orcel found after its last restarts...");
            try { AddMessage(false, await Task.Run(delegate { return Recovery.Read(); })); }
            catch (Exception) { AddMessage(false, "The read-only recovery check failed unexpectedly. No action was performed."); }
        }

        private async void ShowClients()
        {
            AddMessage(false, "Reading connected AI clients from the local runtime...");
            try { AddMessage(false, await Task.Run(delegate { return ConnectedClients.Read(); })); }
            catch (Exception) { AddMessage(false, "The read-only connected clients query failed unexpectedly. No action was performed."); }
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
            expect(!char.IsHighSurrogate(MainWindow.Announcement(new string('a', MainWindow.MaxAnnouncedChars - 1) + "\U0001F600 tail").TrimEnd('…').Last()), "an announcement never ends inside a surrogate pair");
            System.Windows.Controls.Button stopButton = MainWindow.StopButton("Stop desktop control", "StopControlButton");
            System.Windows.Controls.Button plainButton = MainWindow.ActionButton("Refresh status", true, "RefreshButton");
            expect(stopButton.Background != plainButton.Background && stopButton.BorderThickness.Left >= 2 && ((string)stopButton.Content).EndsWith("Stop desktop control") && AutomationProperties.GetName(stopButton) == "Stop desktop control", "the stop button looks different from the others and keeps its plain accessible name");
            expect(Colors.HighContrast || (((SolidColorBrush)Colors.Stop).Color != ((SolidColorBrush)Colors.Accent).Color && ((SolidColorBrush)Colors.OnStop).Color == Color.FromRgb(0x09, 0x0D, 0x19)), "the stop colour differs from the accent and keeps dark text");
            bool legacy;
            expect(AppContext.TryGetSwitch(LegacyAccessibilitySwitch, out legacy) && !legacy, "WPF's legacy accessibility behaviour is off, so live regions reach screen readers");
            TextBlock announcer = new TextBlock();
            MainWindow.ConfigureAnnouncer(announcer);
            expect(AutomationProperties.GetLiveSetting(announcer) == AutomationLiveSetting.Polite && AutomationProperties.GetAutomationId(announcer) == "Announcement" && !announcer.Focusable, "the announcer is a polite live region that never takes focus");
            expect(CommandRouter.Classify("workspaces") == SafeCommand.Workspaces && string.Join(" ", CommandRouter.CliArguments(SafeCommand.Workspaces)) == "workspace list --json" && CommandRouter.Classify("workspace add x c:\\") == SafeCommand.Unsupported, "workspaces lists only; nothing adds a folder");
            string listed = Interpret.WorkspacesMessage(new CliResult { ExitCode = 0, Stdout = "{\n  \"ok\": true,\n  \"workspaces\": [\n    {\"id\": \"main\", \"root\": \"C:\\\\code\", \"trust\": {\"trusted\": true}},\n    {\"id\": \"x\\u202e\", \"root\": \"D:\\\\x\", \"trust\": null}\n  ]\n}" });
            expect(listed.Contains("• main (trusted for STRONG operations): C:\\code") && listed.Contains("• x  (trust unknown): D:\\x") && listed.Contains("never grants a folder") && listed.Split('\n').Length == 4, "workspaces are listed with trust, escaped, one per line");
            expect(Interpret.WorkspacesMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"workspaces\":[]}" }).StartsWith("No workspaces are configured"), "an empty list says how to add one in a terminal");
            foreach (string malformed in new[] { "{\"ok\":true,\"workspaces\":\"x\"}", "{\"ok\":true,\"workspaces\":{}}", "{\"ok\":true,\"workspaces\":[1,2]}" })
                expect(Interpret.WorkspacesMessage(new CliResult { ExitCode = 0, Stdout = malformed }).Contains("form this app understands"), "a malformed list is never reported as no workspaces");
            expect(Interpret.WorkspacesMessage(new CliResult { TimedOut = true }).Contains("waiting for another Orcel command"), "a timeout says what may be holding it");
            expect(CommandRouter.Classify("connect") == SafeCommand.Connect && CommandRouter.CliArguments(SafeCommand.Connect) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Connect), "connect runs nothing");
            string guide = ConnectGuide.Text("C:\\Users\\a b\\.orcel\\bin\\orcel.exe", true);
            expect(guide.Contains("\"command\": \"C:\\\\Users\\\\a b\\\\.orcel\\\\bin\\\\orcel.exe\"") && guide.Contains("claude mcp add --scope user orcel -- 'C:\\Users\\a b\\.orcel\\bin\\orcel.exe' mcp stdio") && guide.Contains("startup_timeout_sec = 20\ntool_timeout_sec = 60") && guide.Contains("command = \"C:\\\\Users\\\\a b\\\\.orcel\\\\bin\\\\orcel.exe\""), "connect shows the exact path, escaped for JSON and TOML, single-quoted for PowerShell");
            expect(ConnectGuide.Text("C:\\Users\\$(calc)\\.orcel\\bin\\orcel.exe", true).Contains("-- 'C:\\Users\\$(calc)\\.orcel\\bin\\orcel.exe' mcp") && ConnectGuide.PowerShellPath("O'Brien") == "O''Brien" && ConnectGuide.PowerShellPath("O\u2019Brien") == "O\u2019\u2019Brien" && ConnectGuide.PowerShellPath("a\u2018b\u201Ac\u201Bd") == "a\u2018\u2018b\u201A\u201Ac\u201B\u201Bd", "the PowerShell line never expands or breaks on the path, curly quotes included");
            expect(ConnectGuide.Text("C:\\Users\\O'Brien\\.orcel\\bin\\orcel.exe", true).Contains("command = \"C:\\\\Users\\\\O'Brien\\\\.orcel\\\\bin\\\\orcel.exe\""), "a path with an apostrophe stays valid TOML");
            string snippet = guide.Split('\n').First(line => line.StartsWith("{ \"mcpServers\""));
            expect(new JavaScriptSerializer().DeserializeObject(snippet) is Dictionary<string, object>, "the Claude Desktop snippet is valid JSON");
            expect(ConnectGuide.Text("x", false).StartsWith("Orcel isn't installed"), "connect without an install says to install first");
            expect(CommandRouter.Classify(" History ") == SafeCommand.History && CommandRouter.CliArguments(SafeCommand.History) == null, "history routes and never runs the CLI");
            expect(AppApi.RequestFrame("approval.history", null).Contains("\"method\":\"approval.history\",\"params\":{\"limit\":10}"), "approval.history frame");
            string history = ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"entries\":[{\"decision\":\"Approved\",\"approval_class\":\"SOFT\",\"workspace_id\":\"ws\\u2028x\",\"decided_at_ms\":1,\"consumed\":true,\"origin\":{\"kind\":\"remote\",\"provider\":\"tunnel\",\"device\":\"d\\u202e1\"}},{\"decision\":\"Denied\",\"approval_class\":\"STRONG\",\"workspace_id\":\"ws\",\"decided_at_ms\":2,\"origin\":null}]}}"));
            expect(history.Split('\n').Length == 4, "one line per decision; a field cannot add lines");
            expect(ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"ledger\":\"busy\",\"entries\":[{\"decision\":\"Approved\",\"approval_class\":\"SOFT\",\"workspace_id\":\"ws\",\"decided_at_ms\":1}]}}")).StartsWith("The approval history couldn't be read just now") && ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"ledger\":\"something-new\",\"entries\":[]}}")).StartsWith("The approval history couldn't be read just now") && ApprovalHistory.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"ledger\":\"unverifiable\",\"entries\":[]}}")).StartsWith("The approval history failed its integrity check"), "an unverified history says so");
            expect(history.Contains("approved (SOFT), from REMOTE via tunnel, device d 1, workspace ws x, used") && history.Contains("denied (STRONG), from origin not recorded"), "history names decision, class, origin and use");
            expect(CommandRouter.Classify(" Recovery ") == SafeCommand.Recovery && CommandRouter.CliArguments(SafeCommand.Recovery) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Recovery), "recovery routes and never runs the CLI");
            List<Dictionary<string, object>> recovered = new List<Dictionary<string, object>> {
                AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"title\":\"Q3\\u202e\\nreport\",\"proposal\":{\"destination\":\"out/q3.xlsx\"},\"steps\":[{\"kind\":\"approval\",\"outcome\":\"approved\"},{\"kind\":\"reconcile\",\"outcome\":\"unknown\"}]}}"),
                AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"title\":\"Q2\",\"steps\":[{\"kind\":\"reconcile\",\"outcome\":\"nothing_written\"}]}}"),
                AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"title\":\"Q1\",\"steps\":[{\"kind\":\"verify\",\"outcome\":\"passed\"}]}}"),
                null
            };
            Dictionary<string, object> recoveryList = AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[]}}");
            string recoveryText = Recovery.Text(recoveryList, recovered);
            expect(recoveryText.StartsWith("1 report needs your attention.") && recoveryText.Contains("out/q3.xlsx: a file is there, or couldn't be read, and it doesn't check") && recoveryText.Contains("\"Q2\": nothing was written") && !recoveryText.Contains("Q1") && recoveryText.Contains("1 task's details couldn't be read") && recoveryText.Split('\n').Length == 5, "recovery explains each restart check, escaped, one line each, skips tasks without one, and counts tasks it couldn't read");
            expect(Recovery.Text(null, new List<Dictionary<string, object>>()).StartsWith("Recovery check unavailable") && Recovery.Text(recoveryList, new List<Dictionary<string, object>>()).StartsWith("No report was interrupted") && Recovery.Text(recoveryList, new List<Dictionary<string, object>> { null, null }).StartsWith("No interrupted report was found among the tasks that could be read.") && Recovery.Text(recoveryList, new List<Dictionary<string, object>> { null, null }).Contains("2 tasks' details couldn't be read") && Recovery.Meaning("verified").StartsWith("the report is there") && Recovery.Meaning("new-outcome").Contains("doesn't know"), "recovery says when there is nothing to report or no answer, and never guesses an outcome");
            expect(CommandRouter.Classify(" Settings ") == SafeCommand.Settings && CommandRouter.CliArguments(SafeCommand.Settings) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Settings), "settings routes to no CLI command of its own; it reads through the fixed previews, control and workspace queries");
            expect(SettingsView.PreviewsOf(Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"approval_previews\":\"sizes\",\"changed\":false}" })) == SettingsView.PreviewsState.SizesOnly && SettingsView.PreviewsOf(Interpret.PreviewsMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"approval_previews\":\"content\",\"changed\":false}" })) == SettingsView.PreviewsState.Content && SettingsView.PreviewsOf(Interpret.PreviewsMessage(new CliResult { TimedOut = true })) == SettingsView.PreviewsState.Unknown && SettingsView.PreviewsOf(Interpret.PreviewsMessage(new CliResult { FailedToStart = true })) == SettingsView.PreviewsState.Unknown, "settings reads the previews setting from the runtime's own reply, and no answer is unknown");
            expect(SettingsView.ControlOf(Interpret.ControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"full_control\":{\"active\":true}}" })) == SettingsView.ControlState.Active && SettingsView.ControlOf(Interpret.ControlMessage(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"full_control\":{\"active\":false}}" })) == SettingsView.ControlState.Off && SettingsView.ControlOf(Interpret.ControlMessage(new CliResult { TimedOut = true })) == SettingsView.ControlState.Unknown, "settings reads desktop control from the runtime's own reply, and no answer is unknown");
            string settingsText = SettingsView.Text(SettingsView.PreviewsState.SizesOnly, SettingsView.ControlState.Off, 2, SetupGuide.ClientState.Connected, 1);
            string unknownText = SettingsView.Text(SettingsView.PreviewsState.Unknown, SettingsView.ControlState.Unknown, null, SetupGuide.ClientState.Unknown, 0);
            expect(settingsText.StartsWith("Orcel settings (this app only reads them") && settingsText.Contains("Approval previews: sizes only") && settingsText.Contains("orcel approvals previews content") && settingsText.Contains("Desktop control: off. Granting it stays in a terminal") && !settingsText.Contains("stop control") && settingsText.Contains("Folders Orcel may use: 2.") && settingsText.Contains("AI clients connected now: 1."), "settings shows each setting in read-only words, with where it is changed");
            expect(unknownText.Contains("Approval previews: couldn't check.") && unknownText.Contains("Desktop control: couldn't check.") && unknownText.Contains("Folders Orcel may use: couldn't check.") && unknownText.Contains("AI clients connected now: couldn't check.") && !unknownText.Contains("saved") && !unknownText.Contains("may or may not") && !unknownText.Contains("was not changed"), "settings never guesses, and never words a read as a change");
            expect(CommandRouter.Classify(" Setup ") == SafeCommand.Setup && CommandRouter.CliArguments(SafeCommand.Setup) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Setup), "setup routes to no CLI command of its own; it reads through the workspaces command's fixed arguments");
            int setupCount;
            expect(SetupGuide.Clients(null, out setupCount) == SetupGuide.ClientState.Unknown && SetupGuide.Clients(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"ok\",\"clients\":[]}}"), out setupCount) == SetupGuide.ClientState.None && SetupGuide.Clients(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"ok\",\"clients\":[{\"pid\":1},{\"pid\":2}]}}"), out setupCount) == SetupGuide.ClientState.Connected && setupCount == 2 && SetupGuide.Clients(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"unavailable\",\"clients\":[]}}"), out setupCount) == SetupGuide.ClientState.Unknown, "setup reads connected clients and never guesses");
            expect(SetupGuide.Text(false, SetupGuide.ClientState.Unknown, 0).Contains("run .\\orcel.exe install") && SetupGuide.Text(false, SetupGuide.ClientState.Unknown, 0).EndsWith("Next: install Orcel (step 1).") && SetupGuide.Text(true, SetupGuide.ClientState.None, 0).EndsWith("Next: connect a client (step 2).") && SetupGuide.Text(true, SetupGuide.ClientState.Unknown, 0).Contains("couldn't check") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1).Contains("1 client is connected") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 3).EndsWith("then try it (step 4).") && SetupGuide.Text(true, SetupGuide.ClientState.None, 0).Contains("orcel workspace add <id> <folder>"), "setup names what is done and the next step");
            expect(SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 2, true).Contains("3. Choose a folder Orcel may work in: done, 2 folders are set up") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 2, true).Contains("4. Try it: done") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 2, true).EndsWith("Next: nothing; Orcel is set up. Type help for what this app shows."), "a finished setup says so");
            expect(SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 0, false).Contains("3. Choose a folder Orcel may work in: none yet;") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 0, false).EndsWith("Next: choose a folder (step 3).") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, 1, false).EndsWith("Next: try it (step 4).") && SetupGuide.Text(true, SetupGuide.ClientState.Connected, 1, null, null).EndsWith("then try it (step 4)."), "setup names the next step from what it could check, and never guesses");
            expect(SetupGuide.Tried(null, null) == null && SetupGuide.Tried(0, null) == false && SetupGuide.Tried(null, 1) == true && SetupGuide.Tried(2, 0) == true && SetupGuide.Listed(null, "entries") == null && SetupGuide.Listed(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"entries\":\"x\"}}"), "entries") == null && SetupGuide.Listed(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"tasks\":[{\"task_id\":\"t\"}]}}"), "tasks") == 1, "activity is read from decisions and tasks, and unreadable answers are unknown");
            expect(Interpret.WorkspaceCount(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"workspaces\":[{\"id\":\"a\"},{\"id\":\"b\"}]}" }) == 2 && Interpret.WorkspaceCount(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true,\"workspaces\":[]}" }) == 0 && Interpret.WorkspaceCount(new CliResult { TimedOut = true }) == null && Interpret.WorkspaceCount(new CliResult { ExitCode = 0, Stdout = "{\"ok\":true}" }) == null, "workspaces are counted from the runtime's own answer, or unknown");
            expect(!SetupGuide.Complete(false, SetupGuide.ClientState.Connected) && !SetupGuide.Complete(true, SetupGuide.ClientState.Unknown) && SetupGuide.Complete(true, SetupGuide.ClientState.Connected) && SetupGuide.ShowAtLaunch(false) && !SetupGuide.ShowAtLaunch(true), "the checklist shows by itself only before Orcel is installed");
            expect(CommandRouter.Classify(" Clients ") == SafeCommand.Clients && CommandRouter.CliArguments(SafeCommand.Clients) == null && !CommandRouter.CanInvokeInstalledHost(SafeCommand.Clients), "clients routes and never runs the CLI");
            expect(AppApi.RequestFrame("clients.list", null) == "{\"v\":\"orcel-app-api/1\",\"id\":\"desktop\",\"method\":\"clients.list\",\"params\":{}}\n", "clients.list is sent with no parameters");
            string clientsText = ConnectedClients.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"ok\",\"truncated\":false,\"clients\":[{\"pid\":4,\"started_at_ms\":1,\"transport\":\"stdio\",\"workspace_id\":\"ws\",\"client\":{\"name\":\"claude\\u202e\\ncode\",\"version\":\"1.2\",\"verified\":false}},{\"pid\":5,\"started_at_ms\":2,\"transport\":\"stdio\",\"workspace_id\":null,\"client\":{\"name\":null,\"version\":null,\"verified\":false}}]}}"));
            expect(clientsText.StartsWith("AI clients connected now") && clientsText.Contains("not verified") && clientsText.Contains("an unnamed client") && clientsText.Contains("1.2, over stdio") && clientsText.Split('\n').Length == 4 && !clientsText.Contains("\u202e"), "connected clients are listed escaped, one line each, and marked unverified");
            expect(ConnectedClients.Text(null).StartsWith("Connected clients unavailable") && ConnectedClients.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"unavailable\",\"clients\":[]}}")).StartsWith("Connected clients unavailable") && ConnectedClients.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"ok\",\"clients\":[]}}")).StartsWith("No AI clients are connected right now") && ConnectedClients.Text(AppApi.ParseReply("{\"v\":\"orcel-app-api/1\",\"ok\":true,\"result\":{\"registry\":\"ok\",\"clients\":\"x\"}}")).StartsWith("Connected clients unavailable"), "unavailable and empty client lists say so");
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

        /// The in-box compiler marks no target framework, so .NET Framework would run WPF with
        /// its legacy accessibility behaviour, which hides UI Automation live regions. Set
        /// before any WPF type loads.
        internal const string LegacyAccessibilitySwitch = "Switch.UseLegacyAccessibilityFeatures";

        [STAThread]
        private static int Main(string[] args)
        {
            AppContext.SetSwitch(LegacyAccessibilitySwitch, false);
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
