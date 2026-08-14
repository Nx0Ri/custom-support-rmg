package dev.busung.s25uroot

import android.content.Context
import android.net.Uri
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {
    private fun getRawRepoUrl(): String =
        AppPreferences.targetsRepoUrl(context) ?: RAW_REPOSITORY

    private fun getCommitApiUrl(): String {
        val custom = AppPreferences.targetsRepoUrl(context)
        if (custom != null && custom.contains("raw.githubusercontent.com")) {
            // Try to convert raw URL to API URL for commit resolving
            return custom.replace("raw.githubusercontent.com", "api.github.com/repos")
                .replace(Regex("/([^/]+)$"), "/git/ref/heads/$1") // Assuming last part is branch
        }
        return COMMIT_API_URL
    }

    fun loadTargets(): List<TargetProfile> {
        val manifestFile = File(context.filesDir, "cached_manifest.json")
        val manifestBytes = try {
            val commit = resolveMainCommit()
            val bytes = downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
            manifestFile.writeBytes(bytes)
            bytes
        } catch (error: Throwable) {
            if (manifestFile.exists()) {
                manifestFile.readBytes()
            } else {
                throw error
            }
        }
        val commit = try { resolveMainCommit() } catch (e: Exception) { "main" }
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = pinArtifactUrl(profile.exploit.url, commit)),
            kernelSu = profile.kernelSu.copy(url = pinArtifactUrl(profile.kernelSu.url, commit)),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }

        val customExploitUri = AppPreferences.exploitPayloadUri(context)
        val customKernelSuUri = AppPreferences.kernelSuPayloadUri(context)
        
        val exploitDest = File(directory, "cve-2026-43499-app.so")
        val ksuDest = File(directory, "ksud-s25u-kdp")

        val exploit = if (customExploitUri != null) {
            copyCustomPayload(customExploitUri, exploitDest, "exploit", onProgress)
        } else {
            downloadArtifact(
                profile.exploit,
                exploitDest,
                context.getString(R.string.artifact_exploit),
                onProgress,
            )
        }

        val kernelSu = if (customKernelSuUri != null) {
            copyCustomPayload(customKernelSuUri, ksuDest, "KernelSU", onProgress)
        } else {
            downloadArtifact(
                profile.kernelSu,
                ksuDest,
                context.getString(R.string.artifact_kernelsu),
                onProgress,
            )
        }

        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun copyCustomPayload(uriStr: String, destination: File, label: String, onProgress: (String) -> Unit): File {
        onProgress("Using local custom $label...")
        try {
            val uri = Uri.parse(uriStr)
            context.contentResolver.openInputStream(uri)?.use { input ->
                destination.outputStream().use { output -> input.copyTo(output) }
            }
            onProgress("Local $label ready")
            return destination
        } catch (e: Exception) {
            error("Failed to read local custom $label: ${e.message}")
        }
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        if (destination.exists() && destination.length() == artifact.size) {
            onProgress(context.getString(R.string.repo_verified, label) + " (Cached)")
            return destination
        }
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(getCommitApiUrl(), MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "${getRawRepoUrl()}/$commit/$path"

    private fun pinArtifactUrl(url: String, commit: String): String {
        return url;
    }

    fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    companion object {
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/Nx0Ri/s24-dzf2-rmgp/git/ref/heads/main"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/Nx0Ri/s24-dzf2-rmgp"
        private const val MUTABLE_RAW_PREFIX = "$RAW_REPOSITORY/main/"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}