package com.anish.trust_fall.externalstorage

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

object ExternalStorageCheck {
    /**
     * Checks if the application is installed on external storage (e.g., SD card).
     *
     * @param context The application context.
     * @return `true` if the app is installed on external storage, `false` otherwise.
     */
    @SuppressLint("ObsoleteSdkInt", "SdCardPath")
    fun isOnExternalStorage(context: Context?): Boolean {
        if (context == null) return false

        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.ECLAIR_MR1) {
            val pm = context.packageManager
            try {
                val packageInfo = pm.getPackageInfo(context.packageName, 0)
                val appInfo = packageInfo.applicationInfo
                // Safe null check before accessing flags
                appInfo?.let {
                    return (it.flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE) == ApplicationInfo.FLAG_EXTERNAL_STORAGE
                }
            } catch (e: PackageManager.NameNotFoundException) {
                // Package not found; fall through to the next check
            }
        }

        // Fallback check for older SDKs or if other methods fail
        return try {
            val filesDirPath = context.filesDir.absolutePath
            when {
                filesDirPath.startsWith("/data/") -> false
                filesDirPath.contains("/mnt/") || filesDirPath.contains("/sdcard/") -> true
                else -> false
            }
        } catch (e: Throwable) {
            // Catch-all fallback
            false
        }
    }
}
