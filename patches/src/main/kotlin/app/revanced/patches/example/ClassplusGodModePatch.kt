package app.revanced.patches

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.annotation.Patch
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11n
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction10x
import com.android.tools.smali.dexlib2.Opcode

@Patch(
    name = "Classplus God Mode",
    description = "Removes watermarks, unblocks screenshots, and blinds root/ADB security checks.",
    packagename = "co.classplus.app" // Ensure this is the exact package name of the app
)
class ClassplusGodModePatch : BytecodePatch() {

    override fun execute(context: BytecodeContext) {

        // Loop through every single class and method in the app
        context.classes.forEach { mutableClass ->

            // ==========================================
            // 1. NEUTRALIZE WATERMARKS (Overwriting Methods)
            // ==========================================
            val isPrefsClass = mutableClass.type.contains("Lco/classplus/app/data/prefs/PreferencesHelperImpl;")
            val isOrgClass = mutableClass.type.contains("Lco/classplus/app/data/model/login_signup_otp/OrganizationDetails;")

            mutableClass.methods.forEach { method ->

                // If we are inside the Watermark checking methods, rewrite them to return 0 (False)
                if (isPrefsClass || isOrgClass) {
                    if (method.name == "isWatermarkActive" ||
                        method.name == "isPdfWatermarkEnabled" ||
                        method.name == "getIsWatermarkActive" ||
                        method.name == "getIsPdfWatermarkEnabled") {

                        method.implementation?.let { impl ->
                            val instructions = impl.instructions
                            instructions.clear()

                            // Inject Dalvik: `const/4 v0, 0x0`
                            instructions.add(BuilderInstruction11n(Opcode.CONST_4, 0, 0))
                            // Inject Dalvik: `return v0`
                            instructions.add(BuilderInstruction10x(Opcode.RETURN, 0))
                        }
                        }
                }

                // ==========================================
                // 2. BLIND SECURITY CHECKS & UNBLOCK SCREENCAST
                // ==========================================
                method.implementation?.instructions?.forEachIndexed { index, instruction ->

                    // A. Swap Strings for Root and ADB Detection
                    if (instruction is Instruction21c) {
                        val ref = instruction.reference
                        if (ref is StringReference) {
                            when (ref.string) {
                                "adb_enabled" -> instruction.reference = StringReference("adb_disabled")
                                "test-keys" -> instruction.reference = StringReference("safe-keys")
                                "/system/xbin/su" -> instruction.reference = StringReference("/system/xbin/sx")
                                "/system/app/Superuser.apk" -> instruction.reference = StringReference("/system/app/Superfake.apk")
                            }
                        }
                    }

                    // B. Kill FLAG_SECURE (0x2000 / 8192) for Screenshots
                    if (instruction.opcode.name == "const/16" && instruction is Instruction11n) {
                        if (instruction.narrowLiteral == 8192L) {
                            // Change the value being loaded from 8192 (0x2000) to 0 (0x0)
                            val register = instruction.registerA
                            method.implementation!!.instructions[index] = BuilderInstruction11n(Opcode.CONST_16, register, 0)
                        }
                    }
                }
            }
        }
    }
}
