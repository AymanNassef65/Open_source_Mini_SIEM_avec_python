import subprocess
import time
import os
import sys

def start_siem():
    # تحديد مسار البايثون داخل الـ venv (للوندوز)
    python_path = os.path.join("venv", "Scripts", "python.exe")
    
    # تأكد أن الـ venv موجودة، إلا ماكانتش نخدمو بالبايثون العادي
    if not os.path.exists(python_path):
        print("[!] Warning: venv not found. Using system python.")
        python_path = "python"

    print("🚀 Initializing CyberWolf SIEM System...")
    print("========================================")

    # 1. تصفير قاعدة البيانات (مهم باش تبدا نقي فـ العرض)
    print("[*] Rebuilding Database...")
    subprocess.run([python_path, "init_db.py"])

    # وظيفة مساعدة لفتح نافذة CMD جديدة وتشغيل سكريبت
    def launch(name, script_path, args=None):
        print(f"[*] Launching {name}...")
        cmd = [python_path, script_path]
        if args: cmd.extend(args)
        # استخدام start cmd /k كايخلي النافذة مفتوحة باش تشوف الـ Logs
        subprocess.Popen(f'start "{name}" cmd /k "{python_path} {script_path} {" ".join(args or [])}"', shell=True)

    # 2. تشغيل الـ Dashboard
    launch("SIEM Dashboard", "app.py")
    time.sleep(2)

    # 3. تشغيل المحرك الرئيسي (Engine)
    launch("SIEM Engine", "main.py")

    # 4. تشغيل العميل الميداني (Nexus Sentinel - HIDS/NIDS)
    # ملاحظة: هادا غالباً كايحتاج Admin للصلاحيات ديال الشبكة
    launch("CyberWolf Agent", "modules/RealTime_System_Monitor.py")

    # 5. تشغيل المحاكي (Simulator)
    launch("Attack Simulator", "attack_simulator.py")

    print("\n✅ SYSTEM ONLINE: CGDSTE3 SIEM is now fully operational.")
    print("🔗 Access Dashboard at: http://127.0.0.1:5000")
    print("⌨️  Press Ctrl+C in any window to stop a specific module.")

if __name__ == "__main__":
    try:
        start_siem()
    except KeyboardInterrupt:
        print("\n[!] Shutdown sequence initiated.")