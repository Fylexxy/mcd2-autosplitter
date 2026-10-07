// Minecraft Dungeons II (Steam, PC) - load remover
// Read-only: this script only reads game memory.
// Requires asl-help (https://github.com/just-ero/asl-help) in LiveSplit's Components folder.
// How every signature/offset was found: docs/findings.md. How to fix after a patch: docs/UPDATING.md.
//
// Start / split / reset: provisional defaults chosen by the runner until the mods decide (docs/phase4-options.html).
//   Start  S1: when you gain control after the loading screen from the main menu into the world (setting, on).
//   Splits:    one split each time a main-story (core) quest is completed; one setting per quest.
//   End E3: manual (or split on the last core quest).
//   Reset  R1: never automatic; R2 (on returning to the main menu) is available as a setting (off).
//   Loads  L1 + M1: only loading screens are removed; C2 (pause while the game is closed) is a setting (off).

state("Dungeons-Win64-Shipping") {}

startup
{
    Assembly.Load(File.ReadAllBytes("Components/asl-help")).CreateInstance("Basic");
    vars.Helper.GameName = "Minecraft Dungeons II";
    vars.Helper.AlertLoadless();

    dynamic[,] _settings =
    {
        { "load_removal",     true,  "Pause game time during loading screens",                                          null },
        { "pause_closed",     false, "Also pause game time while the game is closed or crashed",                        null },
        { "start_world_load", true,  "Auto-start when you gain control after loading from the main menu into the world", null },
        { "reset_menu",       false, "Auto-reset when returning to the main menu",                                      null },
        { "debug_log",        false, "Debug: log world / loading / quest changes (view with DebugView)",               null },
    };
    vars.Helper.Settings.Create(_settings);

    // Core (main story) quests by internal ID, in story order as far as known. Titles come from the quest
    // descriptors' internal names; IDs without one are labelled by part. See docs/findings.md.
    vars.CoreQuests = new List<Tuple<string, string>>
    {
        Tuple.Create("CA00",   "Escape from Camp"),
        Tuple.Create("CA01",   "Plains A1 main quest"),
        Tuple.Create("CA01_B", "Merchant unlock (CA01 part B)"),
        Tuple.Create("CA02",   "Following the Trail"),
        Tuple.Create("CA02_B", "The Wandering Witch"),
        Tuple.Create("CA02_C", "CA02 part C"),
        Tuple.Create("CA03",   "Following the Trail (CA03)"),
        Tuple.Create("CA04",   "Search for the Noteblocks"),
        Tuple.Create("CA05",   "In From the Cold"),
        Tuple.Create("CA06",   "Volca-No"),
        Tuple.Create("CA07",   "Eye of the Storm"),
        Tuple.Create("CA08",   "Lost Harmonies"),
        Tuple.Create("CA08_B", "CA08 part B"),
        Tuple.Create("CA09",   "Source of the Soul Crisis"),
        Tuple.Create("CA10",   "Carapace A1 main quest"),
    };
    settings.Add("quest_splits", true, "Split when a main quest is completed");
    foreach (var q in vars.CoreQuests)
        settings.Add("q_" + q.Item1, true, q.Item1 + "  " + q.Item2, "quest_splits");
    settings.Add("q_other", true, "Other main quests (not in this list, e.g. after a game update)", "quest_splits");
    settings.Add("quest_any", false, "Testing: also split on side / event quests");

    vars.Log = (Action<string>)(msg => print("[MCD2] " + msg));
}

init
{
    // ------------------------------------------------------------------ version
    // FileVersion is always "UE5-CL-0". The game is a Microsoft GDK build on every PC store; its package
    // manifest (MicrosoftGame.config, 3 folders above the exe) holds a store-independent version like 1.1.1.0.
    // Module size + PE TimeDateStamp identify the exact binary in the log.
    IntPtr baseAddr = game.MainModule.BaseAddress;
    int moduleSize = vars.Helper.GetMemorySize();
    int peOffset = vars.Helper.Read<int>(baseAddr + 0x3C);
    uint peStamp = vars.Helper.Read<uint>(baseAddr + peOffset + 0x8);
    string exePath = game.MainModule.FileName;
    string storeName = exePath.IndexOf("steamapps", StringComparison.OrdinalIgnoreCase) >= 0 ? "Steam"
                 : exePath.IndexOf("XboxGames", StringComparison.OrdinalIgnoreCase) >= 0
                   || exePath.IndexOf("WindowsApps", StringComparison.OrdinalIgnoreCase) >= 0 ? "Xbox app"
                 : "Unknown store";
    string pkgVersion = "?";
    try
    {
        string cfg = Path.Combine(Path.GetDirectoryName(exePath), "..", "..", "..", "MicrosoftGame.config");
        var m = System.Text.RegularExpressions.Regex.Match(File.ReadAllText(cfg), "<Identity[^>]*Version=\"([0-9.]+)\"");
        if (m.Success) pkgVersion = m.Groups[1].Value;
    }
    catch (Exception) { }   // the Xbox app may not allow reading the install folder; the version is only a label
    switch (moduleSize)
    {
        case 0xCD94000: version = "1.1.1.0 (" + storeName + ")"; break;   // Steam build 25647713, verified (docs/findings.md)
        default:        version = pkgVersion + " (" + storeName + ", unverified)"; break;
    }
    vars.Log("Attached: " + exePath);
    vars.Log("Store " + storeName + ", package version " + pkgVersion + ", module size 0x" + moduleSize.ToString("X") + ", PE stamp 0x" + peStamp.ToString("X") + " -> version " + version);

    // ------------------------------------------------------------------ signatures
    // Three independent signatures per global; the first that hits wins. target = match + rel + 4 + int32(match + rel) + adj.
    // .text is encrypted on disk and only decrypted at runtime, so these only work against the live process.
    Func<string, object[][], IntPtr> scan = (name, sigs) =>
    {
        foreach (object[] s in sigs)
        {
            IntPtr r = vars.Helper.ScanRel((int)s[0], (string)s[2]);
            if (r != IntPtr.Zero)
            {
                r = r + (int)s[1];
                vars.Log(name + " = module+0x" + ((long)r - (long)baseAddr).ToString("X") + "  (" + (string)s[2] + ")");
                return r;
            }
            vars.Log(name + ": signature missed: " + (string)s[2]);
        }
        return IntPtr.Zero;
    };

    //                                    rel  adj    pattern
    IntPtr gWorld = scan("GWorld", new object[][] {
        new object[] { 3, 0,     "48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 41 B0 01" },   // public UE4SS pattern
        new object[] { 3, 0,     "48 8B 3D ?? ?? ?? ?? 48 8B 5C 24 60" },
        new object[] { 3, 0,     "48 8B 0D ?? ?? ?? ?? 48 8B D8 48 8B 51 18" },
    });
    IntPtr gEngine = scan("GEngine", new object[][] {
        new object[] { 3, 0,     "48 8B 0D ?? ?? ?? ?? 48 8B 89 20 09 00 00 E8 ?? ?? ?? ?? EB ??" },
        new object[] { 3, 0,     "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 88 E8 0F 00 00 48 85 C9 74 ?? 48 8B 01 FF 50 18" },
        new object[] { 3, 0,     "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 89 E8 0F 00 00 48 85 C9 74 ?? 48 8B 01 48 FF 20" },
    });
    IntPtr fNamePool = scan("FNamePool", new object[][] {
        new object[] { 3, 0,     "4C 8D 05 ?? ?? ?? ?? EB ?? 48 8D 0D ?? ?? ?? ?? E8" },              // public pattern
        new object[] { 3, 0,     "48 8D 0D ?? ?? ?? ?? 8B FA 75 ??" },
        new object[] { 3, 0,     "48 8D 05 ?? ?? ?? ?? 48 8B D1 48 8B C8" },
    });

    if (gWorld == IntPtr.Zero || gEngine == IntPtr.Zero || fNamePool == IntPtr.Zero)
    {
        // Most likely a game update changed the code. Retry slowly in case the game is still starting up.
        vars.Log("ERROR: signature scan failed (game updated? see docs/UPDATING.md). Retrying in 3 s.");
        Thread.Sleep(3000);
        throw new InvalidOperationException("[MCD2] signature scan failed");
    }

    // Sanity: FNamePool block 0 starts with the entry "None" (2-byte header, then the string).
    IntPtr block0 = vars.Helper.Read<IntPtr>(fNamePool + 0x10);
    string none = vars.Helper.ReadString(4, ReadStringType.UTF8, block0 + 2);
    if (none != "None")
    {
        vars.Log("FNamePool not ready yet (block0 = '" + none + "'). Retrying in 2 s.");
        Thread.Sleep(2000);
        throw new InvalidOperationException("[MCD2] FNamePool not ready");
    }

    vars.GWorld = gWorld;
    vars.GEngine = gEngine;
    vars.FNamePool = fNamePool;

    // ------------------------------------------------------------------ FName / UObject helpers
    // UE 5.6 layouts (verified live, docs/findings.md):
    //   FNamePool: +0x10 Blocks[]; FName = { u32 ComparisonIndex = block << 16 | offset/2, u32 Number }
    //   FNameEntry header u16: bit0 = wide, len = header >> 6
    //   UObject: +0x10 ClassPrivate, +0x18 NamePrivate (FName), +0x20 OuterPrivate
    //   UStruct: +0x58 PropertiesSize
    vars.NameCache = new Dictionary<uint, string>();
    vars.FNameToString = (Func<ulong, string>)(fName =>
    {
        uint cmp = (uint)(fName & 0xFFFFFFFF);
        uint number = (uint)(fName >> 32);
        string name;
        if (!vars.NameCache.TryGetValue(cmp, out name))
        {
            IntPtr block = vars.Helper.Read<IntPtr>((IntPtr)vars.FNamePool + 0x10 + (int)(cmp >> 16) * 8);
            if (block == IntPtr.Zero) return null;
            IntPtr entry = block + (int)(cmp & 0xFFFF) * 2;
            ushort header = vars.Helper.Read<ushort>(entry);
            int len = header >> 6;
            if (len <= 0 || len > 1023) return null;
            name = (header & 1) != 0
                ? vars.Helper.ReadString(len * 2, ReadStringType.UTF16, entry + 2)
                : vars.Helper.ReadString(len, ReadStringType.UTF8, entry + 2);
            if (name == null) return null;
            vars.NameCache[cmp] = name;
        }
        return number == 0 ? name : name + "_" + (number - 1);
    });
    vars.ObjName = (Func<IntPtr, string>)(obj =>
        obj == IntPtr.Zero ? null : vars.FNameToString(vars.Helper.Read<ulong>(obj + 0x18)));
    vars.ClassName = (Func<IntPtr, string>)(obj =>
        obj == IntPtr.Zero ? null : vars.ObjName(vars.Helper.Read<IntPtr>(obj + 0x10)));

    // ------------------------------------------------------------------ AS_Store (loading signal)
    // GEngine -> UEngine.EngineSubsystemCollection (native TMap<UClass*, USubsystem*>)
    //         -> value for key class "AS_UIStoreSubsystem"
    //         -> +0x40 AS_Store
    //         -> +0xD98 int32 Num of a TArray that is non-empty exactly while a loading screen is requested.
    // The TMap's offset inside UEngine is native (not reflected): try the known value, else scan UEngine for a
    // {Data*, Num, Max} whose first keys are *Subsystem classes. TMap elements are 0x18 bytes {Key, Value, hash}.
    const int SUBSYS_MAP_KNOWN = 0x1168;  // build 25647713
    const int STORE_FROM_SUBSYS = 0x40;   // AS_UIStoreSubsystem -> AS_Store   (verified across a game restart)
    const int STORE_LOADING_NUM = 0xD98;  // AS_Store -> TArray.Num (1-3 while loading; verified across a game restart)
    vars.STORE_LOADING_NUM = STORE_LOADING_NUM;

    // Look up a subsystem by class name in a FSubsystemCollection TMap at owner+mapOff. With strict = true
    // (used while scanning for the map) the first keys must be subsystem classes ("...Subsystem"/"...SubSystem").
    Func<IntPtr, int, bool, string, IntPtr> findInSubsystemMap = (owner, mapOff, strict, className) =>
    {
        IntPtr data = vars.Helper.Read<IntPtr>(owner + mapOff);
        int num = vars.Helper.Read<int>(owner + mapOff + 8);
        int max = vars.Helper.Read<int>(owner + mapOff + 12);
        if (data == IntPtr.Zero || num <= 4 || num > max || max > 4096) return IntPtr.Zero;
        int checkedKeys = 0;
        for (int i = 0; i < num; i++)
        {
            IntPtr key = vars.Helper.Read<IntPtr>(data + i * 0x18);
            string keyName = vars.ObjName(key);
            if (keyName == null) continue;
            if (strict && checkedKeys < 3 && !keyName.ToLowerInvariant().EndsWith("subsystem")) return IntPtr.Zero;
            checkedKeys++;
            if (keyName == className) return vars.Helper.Read<IntPtr>(data + i * 0x18 + 8);
        }
        return IntPtr.Zero;
    };

    // Try the known map offset first; if that fails, scan the owner object for the map and remember the offset.
    vars.FindSubsystem = (Func<IntPtr, string, string, IntPtr>)((owner, offsetKey, className) =>
    {
        int known = vars.MapOffsets[offsetKey];
        IntPtr sub = findInSubsystemMap(owner, known, false, className);
        if (sub != IntPtr.Zero) return sub;
        int size = vars.Helper.Read<int>(vars.Helper.Read<IntPtr>(owner + 0x10) + 0x58);   // UClass.PropertiesSize
        if (size <= 0 || size > 0x10000) size = 0x2000;
        for (int off = 0x28; off < size - 0x10; off += 8)
        {
            sub = findInSubsystemMap(owner, off, true, className);
            if (sub != IntPtr.Zero)
            {
                vars.Log(offsetKey + " subsystem map found at +0x" + off.ToString("X") + " (known value was 0x" + known.ToString("X") + ")");
                vars.MapOffsets[offsetKey] = off;
                return sub;
            }
        }
        return IntPtr.Zero;
    });

    vars.ResolveStore = (Func<IntPtr>)(() =>
    {
        IntPtr engine = vars.Helper.Read<IntPtr>((IntPtr)vars.GEngine);
        if (engine == IntPtr.Zero) return IntPtr.Zero;
        IntPtr sub = vars.FindSubsystem(engine, "Engine", "AS_UIStoreSubsystem");
        if (sub == IntPtr.Zero) return IntPtr.Zero;
        IntPtr store = vars.Helper.Read<IntPtr>(sub + STORE_FROM_SUBSYS);
        return vars.ClassName(store) == "AS_Store" ? store : IntPtr.Zero;
    });

    // Known TMap offsets on build 25647713 (native fields, verified live); the scan fallback handles patches.
    vars.MapOffsets = new Dictionary<string, int> { { "Engine", SUBSYS_MAP_KNOWN }, { "World", 0x930 } };
    vars.Store = IntPtr.Zero;
    vars.StoreCheck = new Stopwatch();
    vars.StoreCheck.Start();
    vars.StoreStatus = "not found yet";

    current.World = "";
    current.LoadingNum = 0;
    current.Loading = false;

    // Diagnostics for ASLVarViewer: loads seen and time spent loading since the script attached.
    vars.LoadCount = 0;
    vars.LoadSeconds = "0.000";
    vars.LoadWatch = new Stopwatch();

    // Start detection: remember whether the current loading screen began while the main menu world was loaded.
    vars.LoadFromMenu = false;
    current.EnteredWorld = false;

    // ------------------------------------------------------------------ quests (splits)
    // GWorld -> UWorld.SubsystemCollection (native TMap, +0x930 on build 25647713, scan fallback)
    //        -> value for key class "QuestRunnerProxySubsystem"
    //        -> +0x48 QuestRunnerProxy (FScriptInterface; first qword = UObject*) = BP_QuestRunner_C actor
    //        -> +0x4C8 Quests (TArray<ULiveQuest*>)
    // ULiveQuest: +0x28 ReferenceQuest (UQuestDescriptor*), +0x50 ID (FString), +0x60 State.State (EQuestState u8)
    // UQuestDescriptor: +0x8C QuestType (EQuestType u8: 0 CoreQuest, 1 SideQuest, 2 ProceduralQuest, 3 EventQuest)
    // EQuestState: 0 NotSet, 1 Locked, 2 Active, 3 Available, 4 Completed, 5 Failed, 6 Unavailable
    // All offsets come from the game's reflection data except the TMap offset (native, verified live).
    vars.ResolveQuestRunner = (Func<IntPtr, IntPtr>)(world =>
    {
        if (world == IntPtr.Zero) return IntPtr.Zero;
        IntPtr proxy = vars.FindSubsystem(world, "World", "QuestRunnerProxySubsystem");
        if (proxy == IntPtr.Zero) return IntPtr.Zero;
        IntPtr runner = vars.Helper.Read<IntPtr>(proxy + 0x48);
        string cls = vars.ClassName(runner);
        return cls != null && cls.Contains("QuestRunner") ? runner : IntPtr.Zero;
    });
    vars.ReadFString = (Func<IntPtr, string>)(addr =>
    {
        IntPtr data = vars.Helper.Read<IntPtr>(addr);
        int num = vars.Helper.Read<int>(addr + 8);
        if (data == IntPtr.Zero || num <= 1 || num > 128) return null;
        return vars.Helper.ReadString((num - 1) * 2, ReadStringType.UTF16, data);   // Num includes the terminator
    });

    vars.QuestRunner = IntPtr.Zero;
    vars.QuestWorld = IntPtr.Zero;
    vars.QuestCheck = new Stopwatch();
    vars.QuestCheck.Start();
    vars.QuestArmed = new Stopwatch();      // splits only fire after the quest list has been stable for a while
    vars.QuestInfo = new Dictionary<IntPtr, Tuple<string, int>>();   // LiveQuest* -> (ID, QuestType)
    vars.QuestState = new Dictionary<IntPtr, int>();                  // LiveQuest* -> last EQuestState
    vars.SplitQueue = new Queue<string>();
    vars.CompletedThisRun = new HashSet<string>();
    vars.KnownCore = new HashSet<string>();
    foreach (var q in vars.CoreQuests) vars.KnownCore.Add(q.Item1);
    vars.QuestStatus = "not found yet";
    vars.LastQuest = "";
}

update
{
    // GWorld -> UWorld; UWorld.NamePrivate (FName at +0x18). "Menu_Spicewood" / "Overworld" / "" while travelling.
    // Read directly (not via a watcher) so a null GWorld shows as "" instead of keeping the previous name.
    IntPtr world = vars.Helper.Read<IntPtr>((IntPtr)vars.GWorld);
    current.World = world == IntPtr.Zero ? "" : (vars.ObjName(world) ?? "");

    // Resolve the AS_Store once per session (it lives for the whole game session); re-validate every 5 s.
    long since = vars.StoreCheck.ElapsedMilliseconds;
    if ((vars.Store == IntPtr.Zero && since > 1000) || since > 5000)
    {
        vars.StoreCheck.Restart();
        if (vars.Store == IntPtr.Zero || vars.ClassName((IntPtr)vars.Store) != "AS_Store")
        {
            IntPtr store = vars.ResolveStore();
            if (store != vars.Store)
            {
                vars.Store = store;
                vars.StoreStatus = store == IntPtr.Zero ? "not found" : "0x" + ((long)store).ToString("X");
                vars.Log("AS_Store: " + vars.StoreStatus);
            }
        }
    }

    current.LoadingNum = vars.Store == IntPtr.Zero ? 0 : vars.Helper.Read<int>((IntPtr)vars.Store + (int)vars.STORE_LOADING_NUM);
    current.Loading = current.LoadingNum > 0 && current.LoadingNum < 64;   // sanity bound against a stale pointer

    current.EnteredWorld = false;
    if (current.Loading && !old.Loading)
    {
        vars.LoadCount++;
        vars.LoadWatch.Start();
        vars.LoadFromMenu = old.World == "Menu_Spicewood" || current.World == "Menu_Spicewood";
    }
    if (!current.Loading && old.Loading)
    {
        vars.LoadWatch.Stop();
        // Menu -> world load finished: the player has control in the world.
        current.EnteredWorld = vars.LoadFromMenu && current.World != "" && current.World != "Menu_Spicewood";
        vars.LoadFromMenu = false;
    }
    vars.LoadSeconds = (vars.LoadWatch.ElapsedMilliseconds / 1000.0).ToString("0.000");

    // ---- quests: (re)resolve the runner when the world changes, otherwise re-check every 2 s until found.
    if (world != vars.QuestWorld || (vars.QuestRunner == IntPtr.Zero && vars.QuestCheck.ElapsedMilliseconds > 2000))
    {
        vars.QuestCheck.Restart();
        vars.QuestWorld = world;
        IntPtr runner = vars.ResolveQuestRunner(world);
        if (runner != vars.QuestRunner)
        {
            vars.QuestRunner = runner;
            vars.QuestInfo.Clear();
            vars.QuestState.Clear();
            vars.QuestArmed.Restart();
            vars.QuestStatus = runner == IntPtr.Zero ? "not found" : "0x" + ((long)runner).ToString("X");
            vars.Log("QuestRunner: " + vars.QuestStatus + " in world '" + current.World + "'");
        }
    }

    if (vars.QuestRunner != IntPtr.Zero)
    {
        IntPtr runner = vars.QuestRunner;
        IntPtr arr = vars.Helper.Read<IntPtr>(runner + 0x4C8);
        int count = vars.Helper.Read<int>(runner + 0x4D0);
        // Splits are armed only after 3 s of a stable quest list outside loading screens, so quest states that
        // are applied from the save file when a world loads (NotSet -> Completed) never cause a split.
        if (current.Loading) vars.QuestArmed.Restart();
        bool armed = !current.Loading && vars.QuestArmed.ElapsedMilliseconds > 3000;
        if (arr == IntPtr.Zero || count <= 0 || count > 2048)
        {
            vars.QuestRunner = IntPtr.Zero;
            vars.QuestStatus = "lost";
        }
        else
        {
            for (int i = 0; i < count; i++)
            {
                IntPtr q = vars.Helper.Read<IntPtr>(arr + i * 8);
                if (q == IntPtr.Zero) continue;
                if (!vars.QuestInfo.ContainsKey(q))
                {
                    string id = vars.ReadFString(q + 0x50);
                    if (id == null) continue;
                    IntPtr desc = vars.Helper.Read<IntPtr>(q + 0x28);
                    int type = desc == IntPtr.Zero ? -1 : vars.Helper.Read<byte>(desc + 0x8C);
                    vars.QuestInfo[q] = Tuple.Create(id, type);
                }
                int state = vars.Helper.Read<byte>(q + 0x60);
                int prev;
                if (vars.QuestState.TryGetValue(q, out prev) && prev != state)
                {
                    var info = vars.QuestInfo[q];
                    if (settings["debug_log"]) vars.Log("Quest " + info.Item1 + " (type " + info.Item2 + "): " + prev + " -> " + state + (armed ? "" : " [not armed]"));
                    // Active (2) -> Completed (4) while armed = the player just finished this quest.
                    if (armed && prev == 2 && state == 4 && !vars.CompletedThisRun.Contains(info.Item1))
                    {
                        vars.LastQuest = info.Item1;
                        bool isCore = info.Item2 == 0;
                        bool want = isCore
                            ? settings["quest_splits"] && (vars.KnownCore.Contains(info.Item1) ? settings["q_" + info.Item1] : settings["q_other"])
                            : settings["quest_any"];
                        if (want)
                        {
                            vars.CompletedThisRun.Add(info.Item1);
                            vars.SplitQueue.Enqueue(info.Item1);
                        }
                    }
                }
                vars.QuestState[q] = state;
            }
        }
    }

    if (settings["debug_log"])
    {
        if (current.World != old.World) vars.Log("World: '" + old.World + "' -> '" + current.World + "'");
        if (current.Loading != old.Loading) vars.Log("Loading: " + old.Loading + " -> " + current.Loading + " (Num " + current.LoadingNum + ")");
    }
}

isLoading
{
    return settings["load_removal"] && current.Loading;
}

start
{
    if (settings["start_world_load"] && current.EnteredWorld)
    {
        vars.Log("Start: entered world '" + current.World + "' from the main menu");
        return true;
    }
}

split
{
    if (vars.SplitQueue.Count > 0)
    {
        string id = vars.SplitQueue.Dequeue();
        vars.Log("Split: quest " + id + " completed");
        return true;
    }
}

onStart
{
    vars.CompletedThisRun.Clear();
    vars.SplitQueue.Clear();
}

onReset
{
    vars.CompletedThisRun.Clear();
    vars.SplitQueue.Clear();
}

reset
{
    // World name goes Overworld -> "" -> Menu_Spicewood when quitting to the menu.
    return settings["reset_menu"] && current.World == "Menu_Spicewood" && old.World != "Menu_Spicewood";
}

exit
{
    vars.Log("Game process exited.");
    // isLoading isn't evaluated while the game is closed, so set the pause state explicitly.
    timer.IsGameTimePaused = settings["pause_closed"];
}
