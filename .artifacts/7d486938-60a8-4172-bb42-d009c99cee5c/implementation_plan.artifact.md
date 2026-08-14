# Fix UI Issues and Update Installation/Settings Logic

The goal is to fix several UI glitches in the installation screen, refine the retry counter logic, remove the system hygiene cleanup, and expand the settings to allow more customization (custom payloads, repo URLs, and KernelSU manager links). Additionally, the auto-reboot logic will be updated to be cancellable with a 10-second countdown and use a direct root reboot.

## User Review Required

> [!IMPORTANT]
> The "System Hygiene" feature is being removed, meaning temporary exploit files will remain on the device in `/data/local/tmp/`. This is as requested by the user.

> [!WARNING]
> Settings now include fields for custom repository URLs and APK manager links. Incorrect values here may break the ability to resolve targets or download the manager app.

## Proposed Changes

### [Component] Core Logic & Preferences

#### [MODIFY] [AppPreferences.kt](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/java/dev/busung/s25uroot/AppPreferences.kt)
- Add preference keys for `EXPLOIT_PAYLOAD_URI`, `KERNELSU_PAYLOAD_URI`, `KERNELSU_APK_URL`, and `TARGETS_REPO_URL`.
- Implement getter/setter methods for these.
- Deprecate `CUSTOM_PAYLOAD_URI` and migrate its value to `EXPLOIT_PAYLOAD_URI` if present.

#### [MODIFY] [PayloadRepository.kt](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/java/dev/busung/s25uroot/PayloadRepository.kt)
- Update `RAW_REPOSITORY` and `COMMIT_API_URL` logic to check for a custom repo URL in preferences.
- Update `download()` to handle separate custom URIs for exploit and KernelSU payloads.

#### [MODIFY] [InstallViewModel.kt](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/java/dev/busung/s25uroot/InstallViewModel.kt)
- Fix the retry counter regex to specifically look for exploit attempts: `Regex("\\[\\+\\] exploit attempt=(\\d+/\\d+)")`.
- Remove the `rm` command in `installKernelSu` to keep temporary files.
- Add `rootReboot()` method that executes `su -c reboot` for instant reboot.

---

### [Component] UI Improvements

#### [MODIFY] [InstallActivity.kt](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/java/dev/busung/s25uroot/InstallActivity.kt)
- Update `InstallScreen`:
    - Set `countdown` default to 10 seconds.
    - Update auto-reboot `LaunchedEffect` to use `installViewModel.rootReboot()` if not cancelled.
    - Add bottom padding to the main `Column` to prevent the log from touching the screen bottom.
- Update `InstallerLog`:
    - Refactor `weight` logic to only apply when expanded, preventing the "gray area" issue when collapsed.
    - Improve animations for a smoother transition.
- General UI cleanup for a "cleaner" look.

#### [MODIFY] [MainActivity.kt](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/java/dev/busung/s25uroot/MainActivity.kt)
- Update `SettingsPage`:
    - Add UI for picking separate Exploit and KernelSU payloads.
    - Add `TextField` for custom KernelSU APK link.
    - Add `TextField` for custom Targets Repo URL.
- Update `openKernelSuManager` to use the custom URL from preferences if set.
- General UI pass for better aesthetics and cleaner layout.

#### [MODIFY] [strings.xml](file:///C:/Users/Ori/StudioProjects/custom-support-rmg/app/src/main/res/values/strings.xml)
- Add strings for new settings fields and updated UI labels.

## Verification Plan

### Automated Tests
- Run `ExploitUidTest` if possible to ensure the exploit execution flow remains functional.

### Manual Verification
- Deploy to a device.
- Verify that the log dropdown closes completely without leaving a weighted empty space.
- Verify that the retry counter only increments for exploit attempts.
- Check the settings page for new fields and ensure they persist correctly.
- Verify the 10-second auto-reboot countdown and its cancellation logic.
- Verify that temporary files are NOT deleted after a successful install.
