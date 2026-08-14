package dev.busung.s25uroot

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.io.InputStream
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

enum class InstallPhase {
    Checking,
    Ready,
    Downloading,
    Exploiting,
    LoadingKernelSu,
    Installed,
    Failed,
}

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
    val fullLog: String = "",
    val bootstrapAcquired: Boolean = false,
    val jailbreakActive: Boolean = false, // Root acquired but KSU might be missing
    val currentAttempts: String = ""
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )
}

data class TargetCatalogUiState(
    val loading: Boolean = false,
    val profiles: List<TargetProfile> = emptyList(),
    val error: String? = null,
)

private data class CommandResult(val code: Int, val output: String)

class InstallViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val repository = PayloadRepository(application)
    private val historyStore = InstallHistoryStore(application)
    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableHistory = MutableStateFlow(historyStore.closeInterruptedRuns())
    private val mutableTargetCatalog = MutableStateFlow(TargetCatalogUiState())
    private var discoveryJob: Job? = null
    private var installJob: Job? = null
    private var activeHistoryEntry: InstallHistoryEntry? = null
    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val history: StateFlow<List<InstallHistoryEntry>> = mutableHistory.asStateFlow()
    val targetCatalog: StateFlow<TargetCatalogUiState> = mutableTargetCatalog.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        if (installJob?.isActive == true) return
        mutableHistory.value = historyStore.load()
        discoveryJob?.cancel()
        discoveryJob = viewModelScope.launch(Dispatchers.IO) {
            val probe = NativeProbe.run()
            val ksuActive = NativeProbe.isKernelSuActive()
            val jbActive = isJailbreakRootActive()

            if (ksuActive) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Installed,
                    message = app.getString(R.string.status_ksu_functional),
                    probeOutput = probe,
                    log = probe,
                    fullLog = probe,
                )
                return@launch
            }

            if (jbActive) {
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_jb_active_ksu_missing),
                    probeOutput = probe,
                    log = probe,
                    fullLog = probe,
                    jailbreakActive = true
                )
                return@launch
            }

            try {
                val profile = repository.resolveTarget(DeviceSnapshot.current())
                val initialLog = "$probe\n${app.getString(R.string.log_profile, profile.profileId)}"
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Ready,
                    message = app.getString(R.string.status_not_installed),
                    probeOutput = probe,
                    log = initialLog,
                    fullLog = initialLog,
                )
            } catch (error: Throwable) {
                val errorLog = "$probe\n[-] ${error.message ?: error.javaClass.simpleName}"
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Failed,
                    message = app.getString(R.string.status_support_failed),
                    probeOutput = probe,
                    log = errorLog,
                    fullLog = errorLog,
                )
            }
        }
    }

    fun fullReboot() {
        viewModelScope.launch(Dispatchers.IO) {
            if (shizukuEnabled() && ShizukuController.isGranted()) {
                ShizukuController.exec(arrayOf("svc", "power", "reboot")).waitFor()
            } else {
                try { 
                    Runtime.getRuntime().exec(arrayOf("su", "-c", "svc power reboot || setprop sys.powerctl reboot || reboot")).waitFor() 
                } catch(e:Exception){
                    try { Runtime.getRuntime().exec(arrayOf("reboot")).waitFor() } catch(_:Exception){}
                }
            }
        }
    }

    fun forceFullReboot() {
        viewModelScope.launch(Dispatchers.IO) {
            // First try Shizuku as it is most official
            if (shizukuEnabled() && ShizukuController.isRunning()) {
                try { ShizukuController.exec(arrayOf("svc", "power", "reboot")).waitFor() } catch(_:Exception){}
            }
            // Then try su reboot
            try { 
                Runtime.getRuntime().exec(arrayOf("su", "-c", "svc power reboot || setprop sys.powerctl reboot || reboot")).waitFor() 
            } catch(e:Exception){
                // Direct reboot fallback
                try { Runtime.getRuntime().exec(arrayOf("reboot")).waitFor() } catch(_:Exception){}
            }
        }
    }

    fun softReboot() {
        viewModelScope.launch(Dispatchers.IO) {
            if (shizukuEnabled() && ShizukuController.isGranted()) {
                ShizukuController.exec(arrayOf("setprop", "ctl.restart", "zygote")).waitFor()
            } else {
                try { Runtime.getRuntime().exec(arrayOf("su", "-c", "setprop ctl.restart zygote")).waitFor() } catch(e:Exception){}
            }
        }
    }

    fun instantSoftReboot() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // Direct root reboot via terminal, instantly
                Runtime.getRuntime().exec(arrayOf("su", "-c", "setprop ctl.restart zygote")).waitFor()
            } catch (e: Exception) {
                // Fallback to existing softReboot if su fails or isn't available as expected
                softReboot()
            }
        }
    }

    fun installKernelSuOnly(profileId: String? = null) {
        if (installJob?.isActive == true || NativeProbe.isKernelSuActive()) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            startHistory()
            try {
                setPhase(InstallPhase.Checking, "Using active jailbreak root, preparing KernelSU...")
                val profile = if (profileId == null) repository.resolveTarget(DeviceSnapshot.current()) else repository.resolveTarget(profileId)
                updateHistoryProfile(profile.profileId)
                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(payloads)
                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_functional))
                appendLog("[+] KernelSU module loaded via active jailbreak root")
                finishHistory(InstallRunResult.Succeeded)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            }
        }
    }

    fun installManagerApk() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val customUrl = AppPreferences.kernelSuApkUrl(app)
                val url = if (!customUrl.isNullOrBlank()) customUrl else "https://github.com/tiann/KernelSU/releases/download/v3.2.5/KernelSU_v3.2.5_32525-release.apk"
                
                appendLog("[*] Downloading KernelSU manager APK...")
                val apkFile = File(app.cacheDir, "ksu_manager.apk")
                val bytes = repository.downloadBytes(url, 20 * 1024 * 1024) // 20MB limit
                apkFile.writeBytes(bytes)
                
                appendLog("[*] Installing KernelSU manager via root...")
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "pm install -r ${apkFile.absolutePath}"))
                val exitCode = process.waitFor()
                if (exitCode == 0) {
                    appendLog("[+] KernelSU manager installed successfully")
                } else {
                    appendLog("[-] pm install failed with code $exitCode")
                }
            } catch (e: Exception) {
                appendLog("[-] APK installation failed: ${e.message}")
            }
        }
    }

    private fun isJailbreakRootActive(): Boolean {
        return try {
            // Use a command that definitely requires root and works across Android versions
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "whoami || id"))
            val output = process.inputStream.bufferedReader().use { it.readText() }.lowercase()
            process.waitFor()
            output.contains("root") || output.contains("uid=0")
        } catch (_: Exception) {
            false
        }
    }

    fun deleteHistoryEntries(ids: Collection<String>) {
        val runningId = activeHistoryEntry?.id
        val toDelete = ids.filterNot { it == runningId }
        if (toDelete.isEmpty()) return
        toDelete.forEach(historyStore::delete)
        mutableHistory.value = mutableHistory.value.filterNot { it.id in toDelete }
    }

    fun loadTargetCatalog() {
        if (mutableTargetCatalog.value.loading) return
        viewModelScope.launch(Dispatchers.IO) {
            mutableTargetCatalog.value = TargetCatalogUiState(loading = true)
            mutableTargetCatalog.value = try {
                TargetCatalogUiState(
                    profiles = repository.loadTargets().sortedWith(
                        compareBy(
                            TargetProfile::displayName,
                            TargetProfile::profileId,
                        ),
                    ),
                )
            } catch (error: Throwable) {
                TargetCatalogUiState(error = error.message ?: error.javaClass.simpleName)
            }
        }
    }

    fun forceInstallKernelSu(profileId: String? = null) {
        if (installJob?.isActive == true || mutableState.value.phase == InstallPhase.Installed) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            startHistory()
            try {
                setPhase(InstallPhase.Checking, "Bypassing exploit, preparing KernelSU...")
                val profile = if (profileId == null) repository.resolveTarget(DeviceSnapshot.current()) else repository.resolveTarget(profileId)
                updateHistoryProfile(profile.profileId)
                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(payloads)
                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_functional))
                appendLog("[+] Installation complete (Forced via UI)")
                finishHistory(InstallRunResult.Succeeded)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            }
        }
    }

    fun install(profileId: String? = null) {
        if (installJob?.isActive == true || NativeProbe.isKernelSuActive()) return
        discoveryJob?.cancel()
        installJob = viewModelScope.launch(Dispatchers.IO) {
            // Reset state and immediately set to Checking to avoid "Ready" flicker
            mutableState.value = InstallUiState(
                phase = InstallPhase.Checking,
                message = app.getString(R.string.status_checking_github),
                bootstrapAcquired = false,
                currentAttempts = ""
            )
            startHistory()
            try {
                if (shizukuEnabled()) {
                    appendLog(app.getString(R.string.log_shizuku_prepare))
                    if (!ShizukuController.isRunning() && !ShizukuController.pingUntilRunning()) {
                        error(app.getString(R.string.error_shizuku_unavailable))
                    }
                    if (!ShizukuController.isGranted() && !ShizukuController.requestPermission()) {
                        error(app.getString(R.string.error_shizuku_permission))
                    }
                    appendLog(app.getString(R.string.log_shizuku_permission))
                }
                setPhase(InstallPhase.Checking, app.getString(R.string.status_checking_github))
                val profile = if (profileId == null) {
                    repository.resolveTarget(DeviceSnapshot.current())
                } else {
                    repository.resolveTarget(profileId)
                }
                appendLog(app.getString(R.string.log_profile, profile.profileId))
                updateHistoryProfile(profile.profileId)

                setPhase(InstallPhase.Downloading, app.getString(R.string.status_downloading_payload))
                val payloads = repository.download(profile) { appendLog("[*] $it") }
                appendLog(app.getString(R.string.log_download_verified))

                setPhase(InstallPhase.Exploiting, app.getString(R.string.status_exploit_running))
                executeExploit(payloads.exploit)

                setPhase(InstallPhase.LoadingKernelSu, app.getString(R.string.status_ksu_loading))
                installKernelSu(payloads)

                setPhase(InstallPhase.Installed, app.getString(R.string.status_ksu_functional))
                appendLog(app.getString(R.string.log_install_complete))
                finishHistory(InstallRunResult.Succeeded)
            } catch (error: Throwable) {
                appendLog("[-] ${error.message ?: error.javaClass.simpleName}")
                setPhase(InstallPhase.Failed, app.getString(R.string.status_install_failed))
                finishHistory(InstallRunResult.Failed)
            }
        }
    }

    private suspend fun executeExploit(payload: File) {
        val shizuku = shizukuEnabled()
        val logFile = if (shizuku) File(SHIZUKU_LOG_PATH) else File(app.filesDir, "exploit.log")
        if (shizuku) {
            ShizukuController.exec(arrayOf("rm", "-f", SHIZUKU_LOG_PATH)).waitFor()
        } else {
            logFile.delete()
        }
        val helper = helperFile()
        if (!shizuku) {
            require(helper.canExecute()) { app.getString(R.string.error_helper_unavailable) }
        }
        val logPrefix = mutableState.value.fullLog
        val bootToken = currentBootToken()
        val process = if (shizuku) {
            val stagedPayload = shizukuStage(payload, SHIZUKU_PAYLOAD_PATH, "755")
            ShizukuController.exec(
                arrayOf("/system/bin/sh", "-c", "true"),
                shizukuEnvironment(bootToken, stagedPayload.absolutePath, helper.absolutePath),
            )
        } else {
            val processBuilder = ProcessBuilder(
                helper.absolutePath,
                "--run-payload",
                payload.absolutePath,
                helper.absolutePath,
                logFile.absolutePath,
            ).redirectErrorStream(true)
            processBuilder.environment().apply {
                put("EXPLOIT_ATTEMPTS", EXPLOIT_ATTEMPTS)
                put("P0_ATTEMPT_TIMEOUT_SEC", P0_ATTEMPT_TIMEOUT_SEC)
                put("EXPLOIT_ATTEMPT_TIMEOUT_SEC", EXPLOIT_ATTEMPT_TIMEOUT_SEC)
                cachedP0Offset(bootToken)?.let { put(P0_OFFSET_ENV, it) }
            }
            processBuilder.start()
        }
        val captured = StringBuilder()
        val readLog: () -> String = if (shizuku) {
            { drainProcessOutput(process, captured) }
        } else {
            { logFile.readTextIfPresent() }
        }

        try {
            val startedAt = SystemClock.elapsedRealtime()
            var lastProgressAt = startedAt
            var lastRawLog = ""
            var localBootstrapAcquired = false

            while (process.isAlive) {
                val rawLog = readLog()
                if (rawLog != lastRawLog) {
                    cacheP0Offset(bootToken, rawLog)
                    publishExploitLog(logPrefix, rawLog)
                    lastRawLog = rawLog
                    lastProgressAt = SystemClock.elapsedRealtime()

                    // Match attempt=did/total specifically for exploit runs
                    val attemptMatch = Regex("[+].*exploit.*attempt=(\\d+/\\d+)").findAll(rawLog).lastOrNull()
                    if (attemptMatch != null) {
                        mutableState.value = mutableState.value.copy(currentAttempts = attemptMatch.groupValues[1])
                    }

                    // Detection for early failure: [-] exploit attempt=.* failed
                    if (rawLog.contains("[-] exploit attempt=") && rawLog.contains("failed status=255")) {
                        process.destroy()
                        error(app.getString(R.string.error_exploit_fail_run))
                    }

                    if (rawLog.contains("exploit completed") && rawLog.contains("root=1")) {
                        localBootstrapAcquired = true
                        mutableState.value = mutableState.value.copy(bootstrapAcquired = true)
                        break
                    }
                    if (rawLog.contains("requires P0 discovery") || rawLog.contains("P0 session was consumed")) {
                        bootToken?.let { clearP0Offset(it) }
                        process.destroy()
                        throw java.lang.IllegalStateException("Wasted P0 session. Device reboot required.")
                    }
                }
                val now = SystemClock.elapsedRealtime()
                require(now - lastProgressAt < EXPLOIT_STALL_MILLIS) {
                    app.getString(R.string.error_exploit_stalled)
                }
                require(now - startedAt < EXPLOIT_TOTAL_MILLIS) {
                    app.getString(R.string.error_exploit_timeout)
                }
                delay(if (shizuku) SHIZUKU_LOG_POLL_INTERVAL else LOG_POLL_INTERVAL)
            }

            if (localBootstrapAcquired) {
                var gracePeriod = 25
                while (process.isAlive && gracePeriod > 0) {
                    delay(100)
                    gracePeriod--
                }
                if (process.isAlive) process.destroy()
            } else {
                val exitCode = process.waitFor()
                val rawLog = readLog()
                cacheP0Offset(bootToken, rawLog)
                publishExploitLog(logPrefix, rawLog)

                if (rawLog.contains("full route requires P0 discovery") || rawLog.contains("fresh P0 session was consumed")) {
                    bootToken?.let { clearP0Offset(it) }
                    error("Wasted P0 session. Device reboot required.")
                }

                val earlyOutput = readProcessOutput(process, shizuku).trim()
                require(exitCode == 0) {
                    app.getString(
                        R.string.error_payload_exit,
                        exitCode,
                        earlyOutput.takeIf(String::isNotBlank)?.let { " ($it)" } ?: "",
                    )
                }
                require(rawLog.contains("exploit completed") && rawLog.contains("done=1 root=1")) {
                    app.getString(R.string.error_success_marker)
                }
            }
        } finally {
            if (process.isAlive) {
                process.destroy()
                delay(500.milliseconds)
                if (process.isAlive) process.destroyForcibly()
            }
        }
        appendLog(app.getString(R.string.log_bootstrap_root))
    }

    private fun drainProcessOutput(process: Process, buffer: StringBuilder): String {
        return try {
            drainStream(process.inputStream, buffer)
            drainStream(process.errorStream, buffer)
            buffer.toString()
        } catch (_: Throwable) {
            buffer.toString()
        }
    }

    private fun drainStream(stream: InputStream, buffer: StringBuilder) {
        val data = ByteArray(4096)
        while (stream.available() > 0) {
            val count = stream.read(data)
            if (count <= 0) break
            buffer.append(String(data, 0, count, Charsets.UTF_8))
        }
    }

    private fun formatLogLine(line: String, advanced: Boolean): String? {
        if (advanced) return line
        val l = line.trim()

        if (l.startsWith("[*] Checking") || l.startsWith("[+] Support profile") ||
            l.startsWith("[*] Downloading") || l.startsWith("[+] Payload") ||
            l.startsWith("[*] Running kernel") || l.startsWith("[+] Bootstrap") ||
            l.startsWith("[*] Late-loading") || l.startsWith("[+] KernelSU") ||
            l.startsWith("[*] System hygiene") || l.startsWith("[*] KernelSU active") ||
            l.startsWith("[+] Installation") || l.startsWith("[-] Payload execution failed")) return l

        if (l.startsWith("[+] exploit attempt=")) return l.replace("[+] exploit attempt=", "[+] run exploit attempt=")
        if (l.startsWith("[*] found mm_struct")) return l
        if (l.startsWith("[*] parameters cpu")) return "[*] finding collisions"
        if (l.startsWith("[-] KernelSnitch mm_struct leak failed")) return "[-] couldnt find collisions"
        if (l.startsWith("[*] kernel page prepare mode=")) return l.substringBefore(" elapsed_ms").replace("[*] kernel page prepare mode=1 attempt=", "[*] kernel page prepare attempt=").replace("[*] kernel page prepare mode=0 attempt=", "[*] kernel page prepare attempt=")
        if (l.startsWith("[-] exploit attempt=") && (l.contains("timeout") || l.contains("terminated") || l.contains("failed"))) return l.replace("[-] exploit attempt=", "[-] stop exploit attempt=")
        if (l.startsWith("[*] p0 physical write")) return "[*] p0 write ok"
        if (l.contains("fresh P0 session was consumed") || l.contains("full route requires P0 discovery")) return "[!] wasted P0 session, reboot and try again"
        if (l.startsWith("[+] exploit completed")) return l

        return null
    }

    private fun filterLogs(rawLog: String, advanced: Boolean): String {
        if (advanced) return rawLog
        return rawLog.lines().mapNotNull { formatLogLine(it, false) }.joinToString("\n")
    }

    private fun publishExploitLog(prefix: String, rawLog: String) {
        val cleanRaw = stripAnsi(rawLog)
        val advanced = AppPreferences.advancedLogsMode(app)
        val filtered = filterLogs(cleanRaw, advanced)

        mutableState.value = mutableState.value.copy(
            log = listOf(prefix, filtered).filter(String::isNotBlank).joinToString("\n"),
            fullLog = listOf(prefix, cleanRaw).filter(String::isNotBlank).joinToString("\n")
        )
        updateHistoryLog()
    }

    private fun appendLog(line: String) {
        val cleanLine = stripAnsi(line).trim()
        if (cleanLine.isBlank()) return

        val newFullLog = (mutableState.value.fullLog + "\n" + cleanLine).trim()
        val advanced = AppPreferences.advancedLogsMode(app)
        val formatted = formatLogLine(cleanLine, advanced)

        val newLog = if (formatted != null) {
            (mutableState.value.log + "\n" + formatted).trim()
        } else mutableState.value.log

        mutableState.value = mutableState.value.copy(log = newLog, fullLog = newFullLog)
        updateHistoryLog()
    }

    private fun installKernelSu(payloads: VerifiedPayloads) {
        if (shizukuEnabled()) {
            shizukuStage(payloads.kernelSu, SHIZUKU_KSUD_PATH, "755")
            shizukuStage(payloads.kernelSu, SHIZUKU_KSUD_STAGE_PATH, "755")
            appendLog(app.getString(R.string.log_ksu_staged))
        } else {
            val source = shellQuote(payloads.kernelSu.absolutePath)
            val stageCommand =
                "/system/bin/cp $source /data/local/tmp/ksud-s25u-kdp && " +
                        "/system/bin/cp $source /data/local/tmp/.ksud-stage && " +
                        "/system/bin/chmod 755 /data/local/tmp/ksud-s25u-kdp /data/local/tmp/.ksud-stage"
            val stage = runHelper("-c", stageCommand)
            require(stage.code == 0) { app.getString(R.string.error_ksu_stage, stage.output) }
            appendLog(app.getString(R.string.log_ksu_staged))
        }

        val lateLoad = runHelper("--late-load")
        require(lateLoad.code == 0) {
            app.getString(R.string.error_ksu_verify, lateLoad.code, lateLoad.output)
        }
        if (lateLoad.output.isNotBlank()) appendLog(lateLoad.output)
        storeInstallReceipt()

        appendLog(app.getString(R.string.log_ksu_control_verified))
    }

    private fun detectInstalled(): Boolean {
        if (NativeProbe.isKernelSuActive()) return true
        val bootToken = currentBootToken() ?: return false
        val receipt = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
        return receipt.getString(RECEIPT_BOOT_TOKEN, null) == bootToken &&
                receipt.getBoolean(RECEIPT_VERIFIED, false)
    }

    private fun storeInstallReceipt() {
        val bootToken = currentBootToken() ?: error(app.getString(R.string.error_boot_id))
        val stored = app.getSharedPreferences(INSTALL_RECEIPT, Application.MODE_PRIVATE)
            .edit()
            .putString(RECEIPT_BOOT_TOKEN, bootToken)
            .putBoolean(RECEIPT_VERIFIED, true)
            .commit()
        require(stored) { app.getString(R.string.error_receipt) }
    }

    private fun currentBootToken(): String? = runCatching {
        File("/proc/sys/kernel/random/boot_id")
            .readText(Charsets.US_ASCII)
            .trim()
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun cachedP0Offset(bootToken: String?): String? {
        if (bootToken == null) return null
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) != bootToken) return null
        return stored.getString(P0_CACHE_OFFSET, null)
    }

    private fun clearP0Offset(bootToken: String) {
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken) {
            stored.edit().remove(P0_CACHE_OFFSET).apply()
        }
    }

    private fun cacheP0Offset(bootToken: String?, log: String) {
        if (bootToken == null) return
        val match = P0_OFFSET_PATTERN.findAll(log).lastOrNull() ?: return
        val offset = match.groupValues[1].toLongOrNull(16) ?: return
        if (offset !in 0..P0_OFFSET_MAX || offset and P0_OFFSET_MASK != 0L) return
        val value = "0x${offset.toString(16)}"
        val stored = app.getSharedPreferences(P0_CACHE, Application.MODE_PRIVATE)
        if (stored.getString(P0_CACHE_BOOT_TOKEN, null) == bootToken &&
            stored.getString(P0_CACHE_OFFSET, null) == value
        ) return
        stored.edit()
            .putString(P0_CACHE_BOOT_TOKEN, bootToken)
            .putString(P0_CACHE_OFFSET, value)
            .apply()
    }

    private fun helperFile(): File =
        if (shizukuEnabled()) {
            shizukuStage(nativeHelperFile(), SHIZUKU_HELPER_PATH, "755")
        } else {
            nativeHelperFile()
        }

    private fun nativeHelperFile() = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")

    private fun shizukuEnabled(): Boolean = AppPreferences.shizukuMode(app)

    private fun shizukuStage(source: File, target: String, mode: String): File {
        val staged = File(target)
        if (staged.exists() && staged.length() == source.length()) return staged
        try {
            ShizukuController.writeFile(target, mode, source.inputStream())
        } catch (error: Throwable) {
            throw IllegalStateException(
                app.getString(R.string.error_shizuku_stage, target, error.message.orEmpty()),
                error,
            )
        }
        return staged
    }

    private fun shizukuEnvironment(
        bootToken: String?,
        payloadPath: String,
        helperPath: String,
    ): Array<String> = buildList {
        add("EXPLOIT_ATTEMPTS=$EXPLOIT_ATTEMPTS")
        add("P0_ATTEMPT_TIMEOUT_SEC=$P0_ATTEMPT_TIMEOUT_SEC")
        add("EXPLOIT_ATTEMPT_TIMEOUT_SEC=$EXPLOIT_ATTEMPT_TIMEOUT_SEC")
        add("CVE43499_ROOT_HELPER=$helperPath")
        add("LD_PRELOAD=$payloadPath")
        cachedP0Offset(bootToken)?.let { add("$P0_OFFSET_ENV=$it") }
    }.toTypedArray()

    private fun readProcessOutput(process: Process, shizuku: Boolean): String {
        val stdout = process.inputStream.bufferedReader().use { it.readText() }
        val stderr = if (shizuku) process.errorStream.bufferedReader().use { it.readText() } else ""
        return stdout + stderr
    }

    private fun runHelper(vararg arguments: String): CommandResult {
        val helper = helperFile()
        val process = if (shizukuEnabled()) {
            ShizukuController.exec(arrayOf(helper.absolutePath) + arguments)
        } else {
            ProcessBuilder(listOf(helper.absolutePath) + arguments)
                .redirectErrorStream(true)
                .start()
        }
        val output = readProcessOutput(process, shizukuEnabled())
        return CommandResult(process.waitFor(), stripAnsi(output.trim()))
    }

    private fun shellQuote(value: String) = "'${value.replace("'", "'\\''")}'"

    private fun setPhase(phase: InstallPhase, message: String) {
        mutableState.value = mutableState.value.copy(phase = phase, message = message)
        appendLog("[*] $message")
    }

    private fun startHistory() {
        val entry = historyStore.create()
        activeHistoryEntry = entry
        publishHistory(entry)
    }

    private fun updateHistory(transform: (InstallHistoryEntry) -> InstallHistoryEntry) {
        val entry = activeHistoryEntry ?: return
        val updated = transform(entry)
        activeHistoryEntry = updated
        historyStore.save(updated)
        publishHistory(updated)
    }

    private fun updateHistoryLog() =
        updateHistory { it.copy(log = mutableState.value.fullLog) }

    private fun updateHistoryProfile(profileId: String) =
        updateHistory { it.copy(profileId = profileId) }

    private fun finishHistory(result: InstallRunResult) {
        updateHistory { entry ->
            entry.copy(
                completedAtMillis = System.currentTimeMillis(),
                result = result,
                log = mutableState.value.fullLog,
            )
        }
        activeHistoryEntry = null
    }

    private fun publishHistory(entry: InstallHistoryEntry) {
        mutableHistory.value = (mutableHistory.value.filterNot { it.id == entry.id } + entry)
            .sortedByDescending(InstallHistoryEntry::startedAtMillis)
    }

    private fun File.readTextIfPresent(): String = if (exists()) readText() else ""

    companion object {
        private const val EXPLOIT_ATTEMPTS = "30"
        private const val P0_ATTEMPT_TIMEOUT_SEC = "60"
        private const val EXPLOIT_ATTEMPT_TIMEOUT_SEC = "240"
        private const val EXPLOIT_STALL_MILLIS = 150_000L
        private const val EXPLOIT_TOTAL_MILLIS = 900_000L
        private const val INSTALL_RECEIPT = "install_receipt"
        private const val RECEIPT_BOOT_TOKEN = "kernel_boot_id"
        private const val RECEIPT_VERIFIED = "verified"
        private const val P0_CACHE = "p0_cache"
        private const val P0_CACHE_BOOT_TOKEN = "kernel_boot_id"
        private const val P0_CACHE_OFFSET = "offset"
        private const val P0_OFFSET_ENV = "SLIDE_P0_OFFSET"
        private const val P0_OFFSET_MAX = 0x1f0000L
        private const val P0_OFFSET_MASK = 0xffffL
        private const val SHIZUKU_LOG_PATH = "/data/local/tmp/ksu-exploit.log"
        private const val SHIZUKU_HELPER_PATH = "/data/local/tmp/ksu-helper"
        private const val SHIZUKU_PAYLOAD_PATH = "/data/local/tmp/ksu-payload"
        private const val SHIZUKU_KSUD_PATH = "/data/local/tmp/ksud-s25u-kdp"
        private const val SHIZUKU_KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private val LOG_POLL_INTERVAL = 150.milliseconds
        private val SHIZUKU_LOG_POLL_INTERVAL = 1.seconds
        private val ANSI_ESCAPE = Regex("\u001B\\[[0-?]*[ -/]*[@-~]")

        private val P0_OFFSET_PATTERN = Regex(
            "slide-kaslr-ok[^\\n]*slide=([0-9a-fA-F]{16})",
        )

        private fun stripAnsi(value: String): String = ANSI_ESCAPE.replace(value, "").replace("\r", "")
    }
}
